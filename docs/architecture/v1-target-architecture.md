# Firmbatch v1 target architecture

**Status:** Canonical implementation specification after repository review — **revision D.1**
**Source:** `firmbatch_v1_target_architecture_5.pdf` (12 pages) and `architecture-v1_4.md` (the rev D.1 Markdown)
**Source revision:** D.1, 6 September 2026 — "Phase 0 supply and the purchased class", resolving the ten review items raised against revision D of the same day. Supersedes revision D (`firmbatch_v1_target_architecture_4.pdf`, `architecture-v1_3.md`) and revision C, 1 September 2026 (`firmbatch_v1_target_architecture_3.pdf`), whose rendering is this file's git history before the Milestone 3.0 adoption.
**Source snapshots:** `docs/architecture/sources/architecture-v1-rev-d-1.md` (current, verbatim) and `docs/architecture/sources/architecture-v1-rev-d.md` (the historical reviewed input); hashes of every reviewed authority, stored or referenced, in `docs/architecture/sources/README.md`
**Settlement authority:** `settlement-model-r1_3.md` (Amendment 4) is canonical for settlement wording; where this file and that one disagree, that one is right
**Review register:** `docs/architecture/rev-d-decision-register.md` — the ten rev D review items, each with its D.1 resolution and source, and the implementation choices that genuinely remain
**Adopted by:** ADR 0008
**Scope:** Product and execution architecture; customer account, billing and delivery sequencing is defined in `docs/firmbatch-v1-roadmap.md`

This document is the version-controlled rendering of the approved Firmbatch v1 target architecture. It preserves the decisions in the source documents in a format that can be reviewed, diffed, linked from code, and used by implementation agents. Section numbers 1–17 are stable anchors: `AGENTS.md`, the `milestone` skill and ADRs 0004–0008 cite them, and §17's invariants are cited by number. Revisions D and D.1 are integrated under that numbering as marked subsections; §18 lists what changed.

The source architecture, its companions and this document define product behavior. They do not authorize infrastructure launches, provider spend, production changes, or external communication. Prices, SKUs, regions, quotas, notice periods and cost figures quoted from the sources are the documents' figures at their capture dates; they require fresh verification before use and are never spending authority.

**This is a target.** Nothing in it is evidence that a capability is implemented; `docs/STATE.md` is the only record of what the code does. The supplied D and D.1 Markdown files open with "Nothing here is implemented" — a target document's disclaimer about itself, not a description of this repository, which carries a merged Milestone 2 foundation (ADRs 0004–0007). Everything revision D and D.1 add is **PLANNED** in `docs/STATE.md` until a milestone builds it.

Markers used below: **[rev D]** flags content new in revision D; **[D.1]** flags a rule revision D.1 states precisely, resolving a rev D review item or adding the qualification tier. There are no open rules carried in this document; the choices the authorities deliberately leave to configuration, contract or measurement are listed in the review register §3 and in §18.

**What rev D changes.** Business plan v3.4's Phase 0 runs v1 first on capacity Firmbatch **buys** — hyperscaler spot in Finland, Frankfurt and Stockholm, with Verda asked to match — and without an operator agent, which moves behind a supplier signature. That changes what v1 is made of, not what it is. Rev D adds a fourth supply class, **purchased spot**, with its own frozen fields and a platform-level **bridge envelope**; a **cost term in routing** while capacity is bought; three hyperscaler spot **drivers** and their reclaim semantics; Gate 1's **measurements as first-class records**; a **usage basis** per supply class; **node-level windows and multi-GPU executions** for whole-node residual and the frontier lane; **measured throughput and `W_min` inputs** in the certification registry; the **evaluation tier**; `auto_accept_below` decided in favour; an optional **provider policy**; cross-cloud egress in the cost table; and the firm tier's definition aligned with the plan. The attempt / delivery-valid / accepted-unit split, the ledgers and the settlement formulas do not change.

**What rev D.1 resolves.** In every case by taking the settlement canon, plan v3.4 or roadmap r2_4 as the authority: the cancellation cause is `operator_platform_failure` and window revocation follows the canon's table, including an operator-asserted `security_stop`; the settlement grouping parameter and the 90-day true-up are stated in the architecture rather than only in the PDF; endpoint metering is defined; the bridge envelope carries the plan's amounts and an accounting definition; Gate 1's protocol and thresholds are named with their owner; the evaluation tier and `auto_accept_below` get precise rules; `provider_policy`'s scope is declared, including what it does not cover; purchase records separate the frozen launch snapshot from append-only usage and invoice adjustments; the attempt's fields are split into frozen terms and measured outcomes; and an internal **qualification** tier breaks the circle between paid quotes and measured throughput.

Vocabulary: **Phase 0**, **Phase P** and **Phase B** are business phases (purchased-capacity launch; signed-supplier extension; frontier and firm extension). **Milestones M0–M8** are the engineering sequence in the roadmap. "Milestone 0" and "Phase 0" are different things.

## 1. System intent

Firmbatch v1 is a multi-tenant, metadata-controlled batch execution service behind a native, provider-independent job API.

- The core operational unit is an immutable **attempt**.
- The commercial unit is an **accepted unit**: delivery-valid work that passes the customer's contracted acceptance policy.
- **Delivery-valid work** says which supplier produced an accepted unit, and is what a Structure B floor is paid on. Those three are deliberately not the same thing.
- Every execution is assigned an explicit **supply class** and, since rev D, a **usage basis** (§12.2).
- Firmbatch decides where and how a job executes; the customer specifies what is required and by when, never the provider. With Phase 0 buying capacity in three clouds and at Verda, that abstraction is the product. **[rev D]**
- Customer payload bytes travel through the payload plane, not through the API or PostgreSQL.

> The customer buys a completed, validated batch job. Firmbatch decides where and how it executes.

## 2. Deployable artifacts and implementation boundaries

The target has three deployable artifacts, **two of them in Phase 0**: **[rev D]**

1. **Control plane:** one Python image, run in three service roles.
2. **Execution worker:** a signed, digest-pinned OCI image carrying the Python/CUDA runtime. In Phase 0 it runs on VMs Firmbatch rents; from Phase P also on operators' clusters. The image is the same everywhere; only the driver and the credentials differ.
3. **Operator capacity agent:** one static Rust or Go binary installed in an operator's cluster. It is built when a supplier signs (roadmap Phase P) and is a target artifact here, not a Phase 0 one. Conflating the three is how "a static binary with no runtime" ends up describing something that is neither.

The architecture does not require Firmbatch-authored C++. The execution image may contain upstream native/CUDA components required by the inference engine, but a custom C++ inference runtime is not a v1 requirement.

The customer application (`app.firmbatch.com`) and the operator-side software are separate products with separate identities (ADR 0003, §17 invariant 11).

### 2.1 Control-plane roles

The three roles share a Python image but run with separate processes, permissions, and responsibilities.

#### Role 1: API

Responsibilities:

- Authentication and tenancy: an API credential resolves to `tenant_id`; scopes apply to every tenant-owned row and S3 key.
- Idempotency: every mutating call takes an idempotency key; a retried request cannot create a second job or repeat a state change.
- Job lifecycle, quote issuance, and quote acceptance — including automatic acceptance under the customer's `auto_accept_below` (§5.4). **[rev D]**
- The evaluation tier: evaluation jobs are admitted under their own cap with no quote (§5.3). **[rev D]**
- Presigned upload and download access. Payload bytes never enter the API process.

Representative native endpoints:

```text
POST /v1/jobs                      create draft, return presigned upload information
POST /v1/jobs/{id}/submit          inputs are uploaded; begin validation
POST /v1/jobs/{id}/accept-quote    accept the immutable quote (skipped when auto_accept_below covers it)
GET  /v1/jobs/{id}                 state, progress, forecast
POST /v1/jobs/{id}/cancel
GET  /v1/jobs/{id}/results         presigned download of results and errors — and, for evaluation jobs, the report
```

#### Role 2: Controller and reconciler

Responsibilities:

- Provider drivers: quote, capacity, launch an execution specification, observe, cancel, usage, reconcile, and offer/accept/revoke windows. Since rev D the implementations include the three hyperscaler spot drivers and Verda (§4.4). **[rev D]**
- Planner: token-estimated shards, not row-count shards, sized from the **measured** throughput the certification registry holds for the profile — not a placeholder figure (§13.3). **[rev D]**
- Admission:
  - Flex work is admitted on expected value and statistical capacity; while capacity is bought, also on the plan's workload-shape rule and inside the bridge envelope (§8.1). **[rev D]**
  - Firm work is admitted on coverage, probability of finish, and region-eligible hedge capacity.
- Router: evaluates `W_min` and expected delivery-valid value for each job using certified profiles only; on purchased capacity it scores expected delivery-valid work **per dollar** (§13.3); every routing choice records its reason. **[rev D]**
- Reconciler: compares Firmbatch state with provider truth; records cause and actor; applies the contractual settlement grouping; reconciles purchase records against the bridge envelope. **[rev D]**
- Measurement: writes Gate 1's per-pool observations as first-class rows (§8.3). **[rev D]**

Provider credentials live with this role, not with the API, validator, canonicalizer, or workers. Supplier credentials are one least-privilege service account per cloud and per supplier account, held by the controller only.

#### Role 3: Validator and canonicalizer

Responsibilities:

- Validator: structural checks and delivery-valid classification, including the attribution key and the Structure B floor basis. Acceptance policy determines accepted and billed units, and produces the evaluation report for evaluation jobs. **[rev D]**
- Canonicalizer: produces one delivery-valid result per request. Requests in one shard may be won by different attempts. Holds no provider keys.

Only this role may promote attempt-scoped output into customer-visible canonical results. The component parsing untrusted model output is not the component that can spend money.

## 3. Core infrastructure

### 3.1 PostgreSQL: the single authority

PostgreSQL is authoritative for all Firmbatch metadata, contracts, state transitions, decisions, and ledgers, including:

- Tenants, credentials, quotas, jobs, and quotes.
- Per-job and per-tenant spend envelopes, and the platform-level **bridge envelope** for purchased capacity (§8.1). **[rev D]**
- Shards, attempts, leases, and fencing tokens.
- Provider-execution ledger: capacity consumed — and, on purchased executions, the **purchase records** that turn consumption into a reconcilable cost (§8.2). **[rev D]**
- Delivery-valid ledger: attributable delivery-valid work by supplier, **per usage basis** (GPU-seconds or requests). **[rev D]**
- Revenue and acceptance ledger: the canonical attempt and customer-accepted units.
- Settlement periods and statements.
- Window offers and acceptances.
- **Measurement records:** allocation, lifetime and preemption observations by pool (§8.3). **[rev D]**
- Global certification registry, which since rev D also holds each profile's measured prefill and decode throughput and its `W_min` inputs (§13.3). **[rev D]**
- Routing and admission decisions.

The **price register** — purchase rates by supplier, region and SKU — is an input to routing; the rate in force is snapshotted on every purchase (§8.2). **[rev D]** Its source is the versioned GPU price register (`gpu_price_register_1.xlsx`, revision 1, 5 September 2026): hyperscaler spot and on-demand by region and SKU, neocloud posted prices and indices, each row carrying a `Captured` date and a source key; the repository's register is loaded from it with source, currency, billing unit, effective time and freshness, and a price list is never a fill rate. **[D.1]**

Every role reads and writes PostgreSQL. Every tenant-owned authoritative row carries `tenant_id`; shared provider and certification records are explicitly global.

### 3.2 Transactional outbox and SQS

State changes and their events are written in one database transaction through a transactional outbox. SQS is a wake-up mechanism only and is never authoritative. Losing or duplicating a message must not corrupt state.

### 3.3 S3 payload plane

- Inputs and manifests are immutable.
- Output prefixes are attempt-scoped.
- A retry never overwrites another attempt.
- Canonical results use tenant-scoped keys.
- Customers access objects only through presigned URLs. The customer application and SDK move payload bytes directly to and from the object store through those URLs; they hold no raw storage credential.
- Payload bytes do not pass through the API, queues, logs, or PostgreSQL.
- S3 is the v1 payload plane for every tenant. A bucket per supplier cloud region, behind the same presigned-URL interface, is the mitigation for cross-cloud egress on the bridge, adopted when the egress bill says so and not before (§16). Until it exists, `provider_policy` cannot exclude the payload plane's cloud (§5.4). **[rev D]**

## 4. Security and execution plane

### 4.1 Execution security domain

An execution security domain is:

```text
tenant_id + model-artifact classification + region
```

In v1, one execution never concurrently serves two tenants. This deliberately trades packing density for isolation; the utilization cost belongs in the cost model. On a node-class execution the same rule costs eight cards of density, and the frontier lane's prices carry it explicitly. **[rev D]**

### 4.2 Operator capacity agent

The operator capacity agent runs in the operator's cluster and:

- Reads scheduler state.
- Emits signed availability envelopes, window offers, and reclaim events.
- Uses outbound-only communication.
- Receives no customer payload.
- Holds no long-lived Firmbatch credential.
- Uses rate-limited, narrowly scoped credentials.
- Treats offers as inputs only: Firmbatch acceptance creates an obligation; a compromised or broken agent cannot invent a payable.

**Phase P.** The agent is built when a supplier signs and provides capacity visibility; it is not on the Phase 0 path. An equivalent operator-owned capacity endpoint may supply the same interface without the agent; its authentication and contract proof still need qualification. Through a provisioning API alone Firmbatch sees prices and availability but not the scheduler, so an API-only supplier — every hyperscaler, and Verda today — is opportunistic or purchased supply only, and the 25–30% nominated tier is not reachable. **[rev D]**

### 4.3 Execution classes

Supply class belongs to an execution, not permanently to a provider.

- **Purchased spot VMs — Google Cloud, Azure, AWS (Phase 0):** one execution may serve many attempts; the cloud's preemption is a reclaim with the cloud as the asserting party and is a measurement, not a settlement event. Bought only against admitted jobs, inside the bridge envelope. **[rev D]**
- **Verda — VM execution:** one execution may serve many attempts. Spot, evictable opportunistic or purchased supply is available without an agent; nominated supply requires the capacity agent or an operator-side capacity endpoint.
- **Lyceum, or another endpoint — endpoint execution:** one execution is bound to one attempt and is vendor-managed. Usage basis is requests; the supplier drops Firmbatch when latency traffic arrives. Opportunistic only; it cannot offer nomination windows and never passes Business Gate 2. Implemented only when an endpoint supplier signs. **[rev D]**
- **Embedded operator pool — Phase P:** long-lived lowest-priority pods, agent installed by default, supporting opportunistic and nominated windows, cards or whole nodes.

### 4.4 Phase 0 spot drivers **[rev D]**

The provider contract (§7) is unchanged; the set of implementations grows by three spot APIs whose reclaim semantics differ. The rows are the source's description at its date, not verified provider behavior.

| Driver | Reclaim signal and notice | Lifetime, stockout, quota | Price | Execution model |
| --- | --- | --- | --- | --- |
| Google Compute Engine, Spot | Preemption notice on the metadata server, ~30 s; instance stopped | No maximum lifetime; `ZONE_RESOURCE_POOL_EXHAUSTED` on create — spread across zones a/b/c and record every refusal | Set per region and family, may change daily; snapshotted at launch | One VM, many attempts; `a3-highgpu-1g`, a single H100 |
| Azure, Spot VMs | Scheduled Events `Preempt`, ~30 s; eviction policy deallocate or delete — choose delete | No maximum; allocation failures and quota per region; repriced per region | Per region and SKU; snapshotted at launch | One VM, many attempts; `NC40ads_H100_v5`, a single H100 NVL 94 GB |
| AWS EC2, Spot | Interruption notice via IMDS, 2 min, plus a rebalance recommendation | Capacity per pool per zone; `InsufficientInstanceCapacity`; prices per pool | Per instance pool, moves continuously; snapshotted at launch | Single-card sizes (`g6e.4xlarge`) and whole nodes (`p5e`, `p4d`, `p6-b300`) — the frontier lane, Phase B |
| Verda, spot | Eviction, with refund-on-eviction billing (the source says verified; not verified by this repository) | Availability flag per location | Posted, a flat 50% of on-demand | One VM, many attempts |
| Lyceum, endpoint | A drop signal per request | Quota and queue time; capacity opaque | Per token, or a share | One execution, one attempt; usage basis requests |

`E[tail]` takes the notice and the commit interval per driver; nothing else in routing knows which cloud it is on. The **measured** notice, not the documented one, is what goes into the registry.

Phase 0 execution is `gpu_count = 1`. All four VM drivers (Google, Azure, AWS, Verda) are Phase 0 target scope; the roadmap sequences them one at a time. A pool that is not qualified is recorded as unavailable and gated off.

## 5. Job lifecycle and customer contract

### 5.1 Lifecycle

```text
draft -> uploaded -> validating -> quoted
      -> admitted -> running -> finalizing
      -> completed | partial | failed | cancelled

evaluation tier:  draft -> uploaded -> validating -> admitted -> running -> finalizing -> completed
                  (no quote; admitted under the evaluation cap; produces a report, not an invoice)
```

Transitions are explicit and persisted. Quote issuance and acceptance are contractual events. An accepted quote is immutable.

Rev D spells the second state `uploaded` where rev C had `uploading`. **[rev D]** The lifecycle kernel merged in Milestone 2.4 registers no machine; the job machine is defined in Milestone 5 with the job tables, and this diagram establishes intent without being edge-complete (ADR 0007 decision 2).

### 5.2 Canonical JobSpec

There is deliberately no provider field.

```json
{
  "input": { "format": "jsonl" },
  "model": { "id": "Qwen/Qwen3-8B-Instruct", "runtime_profile": "vllm-fp8" },
  "service_tier": "flex",
  "deadline": "2026-09-13T18:00:00Z",
  "acceptance_policy": { "id": "policy_17", "version": 3 },
  "region_policy": ["EU"],
  "provider_policy": { "exclude": [] },
  "auto_accept_below": { "amount": 120.00, "currency": "USD" },
  "output": { "format": "jsonl" },
  "idempotency_key": "customer-run-482"
}
```

Firmbatch chooses the provider, GPU class, and execution time. The customer expresses **what** is required and **by when**, never where it runs. `provider_policy` names *whose*, never *where* (§5.4).

The JSONL input may contain OpenAI-style request bodies such as messages, temperature, maximum output tokens, and response format. This compatibility is inside each request; the enclosing job contract remains native to Firmbatch.

`acceptance_policy` is frozen and version-stamped at admission. Under a revenue share the supplier's payment depends on it, so it cannot be changeable after work is done.

`service_tier` is `flex` (the pilot), `firm` (built, dark — §15.2), `evaluation` (§5.3) or `qualification` (§5.5, internal and never customer-visible). **[rev D]** **[D.1]**

### 5.3 Evaluation tier **[rev D]** **[D.1]**

The free 1,000-request evaluation the customer brief sells is a job type, not a special case. An evaluation job has no quote and produces no invoice; it is admitted under its own cap, runs on the same supply, spends the bridge under that cap and is counted against it gross, and returns a **report**. It is the sales motion.

The rules, precise since D.1:

- **One free evaluation per tenant per corpus.** A second evaluation on the same corpus needs a Firmbatch approval recorded on the job.
- **At most 1,000 requests**, with per-evaluation caps on input tokens, output tokens and purchased spend written into its envelope like any other job's. The cap values are configuration, recorded on the evaluation policy (review register §3); the architecture requires that they exist.
- **The report is always produced** — for zero accepted units, and for failed, partial and cancelled jobs, in which case it says so — and carries: the pass rate against the customer's own rules; every failure with the rule that rejected it; cost per thousand accepted units at list price; and the **escalation rate `x`**, defined as roadmap r2_4 defines it — the share of requests that pass only on a larger model — measured per corpus.
- **An evaluation never converts itself into a paid job.** The paid job is a new job with a quote. Evaluation jobs have no quote and are never auto-accepted into anything.

### 5.4 `auto_accept_below` and `provider_policy` **[rev D]** **[D.1]**

`auto_accept_below` is **decided, in favour** (it was an open item in rev C). Phase 0's paying customers are recurring jobs quoted against their invoice, and a human handshake on every run is friction. The rule, precise since D.1:

- The quote is **always issued and stored**, auto-accepted or not; it stays contractual and immutable.
- It is auto-accepted when its **total excluding VAT and payment fees, in the tenant's billing currency (USD unless the contract says otherwise), is less than or equal to the amount**.
- The consent is the JobSpec field itself, **bound to the credential that submitted the job and recorded on the quote**; it **lapses when the quote expires** and is never carried to another job. The quote's validity duration is commercial configuration (review register §3).

`provider_policy` is optional and names *whose*, never *where*: a customer may exclude a provider class or a named subprocessor — an EU region on a US-owned cloud is acceptable to many EU buyers and not to all — and the default is every certified provider inside `region_policy`. It exists because Phase 0 runs on Google, Microsoft and Amazon, all three on the subprocessor list from the first paid job. It is a constraint on routing, not a placement, so the abstraction survives it. Its scope, declared since D.1: in v1 it governs **execution placement only** — first placement, every retry, every move to shared capacity and every hedge. It **does not govern the payload plane**, which is S3 for every tenant until a bucket per supplier cloud exists, so **a customer who excludes Amazon altogether cannot be served in v1**, and the consent text and the subprocessor list say exactly that rather than promising an exclusion the design cannot honour (§17 invariant 13).

### 5.5 Qualification tier **[D.1]**

`service_tier = qualification` is **internal**: jobs on an internal tenant, on allow-listed profiles, capped like any purchase, whose only output is the certification registry's measured throughput and load times and the pool's measurement records (§8.3). It exists because a paid quote needs measured performance and the measurement needs an admitted job, so the first admitted jobs on any new profile or pool are qualification jobs, authorised by a person, and no profile is certified by fiat. Customers never see the tier; the registry does. A qualification job passes the same admission, cap and credential controls as any purchase and spends the bridge gross under its own cap (§8.1).

## 6. Three accounting records

The following records are separate because they answer different commercial and operational questions.

| Record | Granted when | Pays or bills | Reason it stands alone |
| --- | --- | --- | --- |
| Provider execution work | Capacity was consumed, regardless of output quality | What Firmbatch owes the provider or operator — or, on purchased capacity, what the cloud bills | Compute consumption is a billing fact, not a quality fact. |
| Delivery-valid work | Output is structurally valid, attributable, complete, and correctly fenced — in GPU-seconds, or in requests on endpoint supply | Attribution key for each accepted unit; basis of the Structure B floor where one exists | Identifies which supplier produced shipped work; it is not itself the payment base under pure revenue share, and the floor is undefined on purchased and endpoint classes. |
| Customer-accepted units | Output passes the versioned acceptance policy frozen at admission | What the customer is charged for and therefore the revenue-share basis | Separates product acceptance from execution and delivery quality. The gap between delivery-valid and accepted is shared under Structure A, absorbed up to the floor under B, and absorbed entirely on purchased capacity. |

Engineering delivery efficiency:

```text
eta_delivery = delivery-valid attributed work / provider execution work
```

Product acceptance efficiency:

```text
eta_accept = customer-accepted units / delivery-valid units
```

Collapsing these ratios hides whether a bad period came from failed capacity or rejected output. Neither ratio alone is an operator payment base. On purchased capacity `eta_delivery` is also a direct cost: the bridge's cost per delivery-valid hour is `purchase_rate / eta_delivery` plus control overhead, so a worse delivery efficiency is a worse cost of goods. **[rev D]** `R_c` is measured — `NCR / H^DV` — not derived. The settlement canon reports a third ratio beside these two, `eta_realisation` (Net Collected Revenue over the notional value of all delivery-valid units), the value-weighted figure that belongs in a margin calculation; all three are reported and none is collapsed into another.

## 7. Provider contract

The provider abstraction is execution-centric, not worker-centric. **[rev D]** adds the purchased-spot column; the calls are unchanged.

| Call | Purchased spot — Google, Azure, AWS | Verda VM | Lyceum endpoint | Embedded pool, Phase P |
| --- | --- | --- | --- | --- |
| `quote / capacity` | Price by region, zone and SKU from the price register; a create attempt is the only capacity probe, and its refusal is recorded | Spot price and availability by region and GPU class | Vendor-managed: quotas, queue time and execution-start latency are measured; capacity may be unknown | Operator-declared SKUs, caps, and blackout windows |
| `publish_availability_envelope` | Not offered | Standing shape of what may become available, not a commitment | Not offered; capacity is opaque | Operator's residual view by SKU and region |
| `offer_window / accept_window / revoke_window(cause, at)` | Not applicable — nothing to nominate | Requires the capacity agent or an operator-side capacity endpoint; API-only supply is opportunistic or purchased only | Not supported; opportunistic only | Operator offers, as cards or whole nodes (T8), including calendar gaps (T9); Firmbatch accepts only against admitted or forecast work; no unused reservation |
| `launch(execution_spec)` | One VM execution can serve many attempts; `gpu_count` 1 in v1, a node on the frontier lane | One VM execution can serve many attempts | One execution is bound to one attempt | Long-lived lowest-priority pod serves many attempts |
| `observe / cancel` | Instance state and the cloud's preemption signal; delete instance | Poll instance state; delete instance | Poll invocation; cancel invocation | Pod status; yield within contracted grace |
| `usage / reconcile` | Billed seconds against the purchase record; orphan detection; the measurement rows | Billed increments and orphan detection | Billed requests and duplicate-invocation detection | Claimed, delivery-valid, and attributed-revenue hours, with a cause on every cancellation |

A nomination is two-sided. Separate offer, accept, and revoke actions must identify who moved and establish separate liabilities. A single `nominate()` call would hide whether the operator offered capacity or Firmbatch reserved it, and those settle differently.

A "capacity probe" that allocates a real VM is a purchase, not a read-only check.

## 8. Spend envelope

The admitted spend envelope is persisted at admission and enforced by the router. It contains:

- Maximum provider spend.
- Hedge budget.
- Maximum attempts per request.
- Maximum output tokens.
- Maximum simultaneous launches.
- Maximum cumulative launches.
- Latest useful start time.
- Wall-clock kill-by timestamp.
- Rejection-rate stop condition.
- Quote version and expiry.
- Per-tenant aggregate envelope across jobs, which since rev D also carries the evaluation cap for free jobs. **[rev D]**

Concurrency caps alone are insufficient because a defective controller could repeatedly launch billable executions. The hedge budget is the only budget line that may pay for availability rather than output. It exists inside an admitted job's capped envelope and is priced into its quote; capacity is never bought speculatively. A job pinned to the EU can only be hedged on EU-certified capacity, so hedge liquidity is thinnest exactly where the first customers are.

### 8.1 The platform bridge envelope **[rev D]** **[D.1]**

Beside the per-job and per-tenant envelopes there is one platform-level envelope for purchased capacity: a **monthly cap** on purchased GPU spend net of billings, a **total cap**, a **sub-cap per supplier account**, and the rule that a purchase is launched **only for an admitted job — never ahead of demand**.

The amounts and the accounting, from plan v3.4 and precise since D.1:

- **The plan's amounts are a planning range:** $3–5k a month net of billings and $10k in total, carried in plan v3.4's exposure line and graded a *decision* in the definitions register. **The exact configured monthly cap, total cap and per-supplier sub-caps are spend and deployment decisions a human records on the envelope before the first purchase** (review register §3); this document fixes none of them.
- **Enforcement is gross accrued spend.** Every launch reserves its envelope's maximum hours at the frozen rate; usage records replace the reservation as they arrive; provider invoices reconcile the total monthly.
- **Reporting is net** of the customer billings **invoiced** (not collected) for jobs run on purchased capacity in the same calendar month, before credits, refunds and taxes, in USD at the ECB reference rate of the day.
- Evaluation and qualification spend count gross like any other job's.
- The period is the calendar month. **A launch that would breach the monthly or total cap, or its supplier's sub-cap, is refused at admission, not flagged.**
- **Retirement is numeric, not a warning:** no new purchase for a job once a shared placement is eligible for it, and none at all after twelve months from the first purchase without a re-authorisation recorded on the envelope.
- Reporting is weekly against the caps and monthly at reconciliation.

Admission enforces the plan's workload-shape rule on purchased capacity (input-heavy work first: on the source's reading every shape clears at Google's Finland price and only input-heavy work at neocloud prices, so the rule is the margin of safety on the cheaper supply and the constraint on the dearer). Every job carries `movable_to_shared`, the flag that lets its remaining work move to share-priced capacity the day a supplier contract exists. A bridge that is still the supply at month twelve is the merchant model wearing a bridge's clothing, and the envelope is where that is made impossible rather than merely unwise.

### 8.2 Purchase records **[rev D]** **[D.1]**

Every purchased execution writes, at launch and immutably, a **snapshot**: `supplier_account`, region and zone, SKU, and the `purchase_rate` in force when it started. A price can change while an execution runs, so the record then grows **only by appending**: usage and rate intervals taken from the provider's own records as they arrive, and invoice adjustments at reconciliation. **Past cost is never recomputed** from today's register or from a single final price. The provider-execution ledger already records capacity consumed; the purchase record is what turns it into a cost the bridge envelope can be reconciled against and a per-job cost the quote can be checked against. "No counterparty payable" on the purchased class means no operator settlement under A or B; the cloud's invoice exists and is the purchased cost of goods.

### 8.3 Measurement records and Gate 1 **[rev D]** **[D.1]**

Gate 1 decides where the bridge buys, and the same numbers say whether cheap spot is surplus or a hot region's junk. So the controller records, per pool (supplier, region, zone, SKU) and as first-class rows rather than logs: allocation attempts and grants, time to grant, stockouts, instance lifetime before reclaim as P10/P50/P90, preemptions per day and their hour-of-day shape, the notice actually observed, model-load time warm and cold, and `eta_delivery`. These feed `E[tail]` and `E[V]`, and they are the figures the RFQ quotes back to an operator Firmbatch already buys from.

**The protocol, stated since D.1 and owned by plan v3.4 §3.1:** one instance per pool per zone for **seven days**, on the smallest single-GPU SKU, running a **qualification** job (§5.5). The pool **passes** when the median lifetime exceeds sixty minutes, preemptions run at three a day or fewer per instance, and grants succeed on at least four attempts in five. It **fails** when the median sits within a factor of two of `W_min` or grants fail more often than one in five, and the bridge moves to the next supplier. Samples and their provenance are stored, not only the summary; censored live instances and observation windows are preserved when deriving quantiles, and a missing measurement is not a zero failure rate. The plan may change the thresholds; the architecture insists only that they are numbers and that only measured profiles are certified. Listed prices and the `W_min` table's example figures are not measurements, and a single passing run is not "Gate 1 passed" without the plan's evidence requirements.

## 9. Settlement

Net Collected Revenue (NCR) is cash collected for accepted units, less refunds and credits for those units, payment fees, and transaction taxes — and nothing else.

Settlement wording is canonical in `settlement-model-r1_3.md` (Amendment 4); where this section and that document disagree, that document is right. Rev D changes nothing here; it adds two classes the formulas already cover. Rev D.1 restates the grouping parameter and the 90-day true-up here, which the rev D Markdown had left to the PDF. **[rev D]** **[D.1]**

### 9.1 Structure A: revenue share

```text
P_A,m = S_m + C_m
```

The operator shares the acceptance gap and customer credit risk proportionally, with no floor. This is the commercial structure to lead with.

### 9.2 Structure B: protected downside

```text
P_B,m = max(F_m, S_m) + C_m
```

Firmbatch absorbs the acceptance gap and bad debt up to the floor leg. Floors are unconditional on acceptance and collection. This is a negotiated fallback, priced above Structure A because the floor transfers risk to Firmbatch.

### 9.3 Period calculation

For one operator and settlement period:

```text
S_m   = sum over units u of (s_u * NCR_u)
F_m   = sum over attempts a of (f_a * h_a)
P_A,m = S_m + C_m
P_B,m = max(F_m, S_m) + C_m
```

- `s_u` is the share frozen on a unit's canonical attempt: 0.20 on opportunistic units, 0.25 or 0.30 on nominated ones, 0.60–0.75 on endpoint units — all can occur inside one period.
- `f_a` is the floor rate frozen on an attempt; it is zero on purchased and endpoint classes, which carry no floor.
- `h_a` is delivery-valid GPU-hours attributable to the attempt.
- `C_m` is the cancellation credit for the period.

**Grouping (canon §3, restated in D.1).** The `max` is taken **once per operator per settlement month, across all supply classes together** — never per hour, never per class by default, and never pooled across operators. Per-class grouping is the contractual fallback if an operator refuses the month-wide comparison; the reconciler takes the grouping as a **contract parameter**, so the same code implements either. Never add floor and share; doing so pays twice for the same production. Because `Σ max(a, b) ≥ max(Σa, Σb)`, a per-hour or per-class comparison takes the floor in every weak group and the share in every strong one, and systematically overpays; pooling across operators would let one operator's strong share leg mask another's binding floor, and underpays.

The cancellation credit sits outside the `max`. It is charged per payable cancelled GPU-hour from the last committed result to termination so it cannot overlap delivery-valid hours already in the floor leg. Structure A is the `f_a = 0` case of the same reconciler, which is why one reconciler implements all four rows of the table in §9.4.

Revenue per delivery-valid GPU-hour is measured, not derived:

```text
R_c = NCR / delivery-valid GPU-hours
```

It is not generally equal to acceptance ratio multiplied by a uniform contract rate because units may carry different revenue and compute.

**The true-up and settlement timing (canon §4, restated in D.1).** Each settlement period stays open for true-up for **90 days**. Two legs move on different clocks: the **floor leg and the cancellation credits are paid on the statement whatever has been collected**, because they compensate execution rather than revenue; the **share leg — and under Structure B any amount by which it exceeds the floor already paid — is paid on collection**, at the `s_u` frozen on the unit, with collections arriving inside the window settled on the next statement. Nothing is clawed back; a paid floor is final; the true-up moves only in the supplier's favour. Collection state is therefore tracked per invoice.

### 9.4 The purchased and endpoint classes **[rev D]**

| Structure | Formula | Who carries what | When to use it |
| --- | --- | --- | --- |
| A — revenue share | `P_A,m = S_m + C_m` | The operator shares the acceptance gap and the customer's credit risk, proportionally. No floor. | What Firmbatch opens with, in the RFQ and in the room. |
| B — protected downside | `P_B,m = max(F_m, S_m) + C_m` | Firmbatch absorbs the acceptance gap and bad debt, up to the floor leg. | The fallback Firmbatch concedes to, priced above A. Gate 2 passes on either structure. |
| Purchased spot | No counterparty payable — cost of goods, from the purchase record | Firmbatch carries everything: the acceptance gap, the preemptions, the cost of its own redundancy. | Phase 0 only, inside the bridge envelope; retired job by job. |
| Endpoint supply | `S_m` at 60–75% on accepted requests, or a per-token price; no floor | The supplier carries the serving stack and keeps the majority; the acceptance gap is shared proportionally. | A permitted fast lane that never passes Business Gate 2. |

The opening posture, stated once in the canon: both structures are on the table in every RFQ; Firmbatch opens on A, expects the first pilot to sign on B, and moves to A once `eta_accept` and realisation have been measured on real jobs.

## 10. Attempt ledger and settlement cases

### 10.1 Fields frozen on every attempt

Every attempt carries two kinds of field, and D.1 keeps them apart: the frozen terms this section is named for, and the measured outcomes recorded beside them. **[D.1]**

```text
frozen when the work starts, immutable afterwards — the terms
  operator_id · contract_version · supply_class · usage_basis
  window_offer_id · share_bps · floor_rate · acceptance-policy version
  supplier_account · purchase_rate                      (purchased executions)

measured, append-only, known only as the work runs or ends — the outcomes
  delivery_valid_gpu_seconds | delivery_valid_requests  (per the usage basis)
  cancellation_cause · cancellation_actor
  window outcome: honoured | revoked
```

The terms are commercial fields, not operational ones. `share_bps`, `floor_rate` and `purchase_rate` are snapshots of the terms in force at the moment the work ran: without them a renegotiation silently re-prices every historical settlement, a cloud that reprices spot daily leaves no auditable cost behind, and no operator could check a statement against its own records. `supply_class` belongs to the execution and can vary for the same provider: Verda can supply purchased, opportunistic, nominated and hedge execution on the same day under different terms.

A measured outcome **decides eligibility** — whether the step-up vests, whether an execution is payable — and **never rewrites a frozen term or an accepted customer quote**.

### 10.2 Required settlement behavior

| Event | Structure A | Structure B | Purchased spot **[rev D]** | Required ledger record |
| --- | --- | --- | --- | --- |
| Delivered, accepted, paid | Supply-class share rate times NCR | Greater of floor leg or share leg, compared once for the month | Nothing to anyone; the cost is already in the purchase record | `(job, request) -> canonical attempt -> supplier`, acceptance status, and policy version |
| Delivery-valid, rejected by customer policy | Nothing | Hours enter the floor leg | Nothing; the cost stays with Firmbatch | Delivery-valid units with policy ID and version frozen at admission |
| Delivery-valid, loses canonicalization to sibling | Nothing | Hours enter the floor leg | Paid twice, to the cloud | Both attempts and the winning attempt |
| Accepted, collected after month close | True-up in next statement within 90 days | Same, after the floor comparison already made | — | Collection date and settlement month |
| Accepted but never collected | Nothing | Hours remain in the floor leg | — | Invoice collection state, recorded per invoice; a share of zero is zero, nothing is clawed back |
| Operator reclaims before valid output | Nothing | Nothing | A preemption: billed seconds to the cloud, a measurement row for Firmbatch | Reclaim signal, notice, and lost work |
| Firmbatch-caused cancellation | Credit at quoted rate | Credit at quoted rate | Billed seconds, nothing else | One cause from the closed cancellation enum |
| Unexplained termination | Credit at quoted rate | Credit at quoted rate | Billed seconds; a telemetry defect | `unattributed`; instrumentation failure is charged to the party able to fix it |

## 11. Cancellation causes

Cancellation cause is a closed enum. Every cause is decidable from evidence visible to both sides rather than inferred intent. Adding a cause is a contract amendment, not an ordinary code change. The names and the two right-hand columns are the settlement canon's (Amendment 4, §4); rev D.1 aligned the Markdown to them. **[D.1]**

| Cause | Asserted by | Evidence | Execution payable | Revokes accepted window |
| --- | --- | --- | --- | --- |
| `operator_reclaim` | Operator — or the cloud, on purchased spot **[rev D]** | Reclaim signal in operator records at or before termination, or the cloud's preemption notice | No | Yes; window drops to base share |
| `operator_blackout` | Operator | Termination inside a declared blackout window or cap | No | Yes |
| `operator_platform_failure` | Operator | Node, network, or hypervisor failure in platform records | No | No; nobody chose it |
| `firmbatch_reroute` | Firmbatch | Deliberate replacement recorded in routing decision — including a move from purchased to shared capacity **[rev D]** | Yes | No |
| `firmbatch_routing_error` | Firmbatch | Mis-routed, mis-certified, or misconfigured by Firmbatch; also a defect metric | Yes | No |
| `firmbatch_envelope` | Firmbatch | The job's spend envelope, the bridge envelope **[rev D]** or the wall-clock kill-by reached | Yes | No |
| `firmbatch_sibling_won` | Firmbatch | Another attempt promoted for the same requests | Yes | No |
| `firmbatch_deadline_abandoned` | Firmbatch | Job stopped because it could no longer finish in time | Yes | No |
| `customer_cancelled` | Customer | Accepted customer cancellation with timestamp | Yes | No |
| `lease_expiry` | Neither | Lease expired with no reclaim signal and no platform failure | Yes | No |
| `security_stop` | Either; actor decides | Image-digest mismatch, credential revocation, or isolation violation | Firmbatch stop: yes; operator stop: no | Operator-asserted: yes |
| `unattributed` | Neither | Execution ended and neither side can explain it | **Yes** | No |

Two columns carry the weight. **Asserted by** is why `security_stop` is settleable at all: the same event pays or does not depending on which side stopped it, and that is a fact one side can evidence. **Revokes an accepted window** is the second: only operator-side causes revoke — `operator_reclaim`, `operator_blackout`, and a `security_stop` the operator asserts; `operator_platform_failure` does not, because nobody chose it — and a cancellation of Firmbatch's inside a nominated window never costs the operator a premium it earned by honouring the window.

**`unattributed` pays** at the quoted rate `f_c`. It is the only default an operator will sign, and it puts the burden of instrumenting the boundary on the party that can fix it. Every `unattributed` row is a telemetry defect to close, and its share is a reported metric rather than an accepted cost. `f_c` is quoted by the operator (RFQ Q5); without it the enum records disputes without resolving them, so a contract carries both or neither.

On purchased executions the same enum records *why* an execution ended, but nothing is payable to anyone: a hyperscaler's preemption is `operator_reclaim` with the cloud as the asserting party, and it is a measurement — which cloud, which zone, which hour, how much notice — not a settlement event. **[rev D]**

## 12. Window offers and supply classes

### 12.1 Window-offer state machine

```text
publish_availability_envelope(...)   supplier — standing shape, not a commitment
offer_window(...)                    supplier — a bounded offer; earns nothing, commits nobody
accept_window(...)                   Firmbatch — explicit, and only against admitted or forecast work
revoke_window(cause, effective_at)   either side, with a recorded cause

offered -> accepted -> active -> honoured      premium vests
    |                    `----> revoked        base share, nothing carried forward
    +----> rejected                            costs neither side
    `----> expired                             costs neither side
```

Acceptance, not offer, is the commercial event; premium eligibility begins at acceptance. Rejected and expired offers cost neither party. Only an honoured window earns the premium. `honoured` describes the supplier's conduct, not Firmbatch's utilisation: if Firmbatch accepts a window and fails to fill it, the window is still honoured and earns the step-up on whatever revenue it produced, which may be nothing.

Acceptance snapshots:

- Certified GPU class and runtime profile.
- Region.
- The unit — card or whole node — and, when it is a node, the GPU count and NVLink topology. **[rev D]**
- Capacity count.
- Start and expiry.
- Minimum usable window.
- Notice period.
- Required cache state.
- Share step-up in basis points.
- Contract version.

Eligibility is evaluated once against the offered terms and then frozen — otherwise a supplier could offer capacity that is unusable by settlement and still claim the premium, or Firmbatch could tighten the rule after the fact.

**Whole nodes (T8):** a residual that arrives as an NVLink node can be nominated as a node window and filled by one multi-GPU execution; single cards are what v1 runs, so a node window is admitted only for a certified multi-GPU profile (Phase B). **Capacity calendars (T9):** a known idle block is an offer with a future start, and calendar slippage is already priced by the revocation rule. **[rev D]**

A window that was never accepted is ordinary opportunistic residual at the base share, whatever the supplier intended by offering it. The window machine is a Milestone 6 definition and is built and tested dark until a supplier signs (§15.2).

### 12.2 Supply classes

| Class | Share of NCR | Usage basis | Commitments | Routing consequence |
| --- | --- | --- | --- | --- |
| Opportunistic residual | 20% | GPU-seconds | Neither side commits | Default on shared capacity; the router takes available residual capacity |
| Accepted nomination | 25% | GPU-seconds | Operator offers; Firmbatch explicitly accepts only against admitted or forecast work | Admit only if `W >= W_min`, profile is certified, and region is permitted |
| Accepted nomination, stronger terms | 30% | GPU-seconds | Binding notice, certified profile, permitted region, persistent artifact cache, completion distribution above threshold | Eligible for deadline-bearing work; still admitted on job-specific expected value |
| **Purchased spot (Phase 0 bridge)** **[rev D]** | n/a — cost of goods, no counterparty payable | GPU-seconds, billed by the cloud | None; bought only against admitted jobs, inside the bridge envelope | `E[V]` per dollar; shape rule at admission; shared capacity first whenever both exist |
| **Endpoint supply (S5)** **[rev D]** | 60–75%, or a per-token price | Accepted requests, from the supplier's usage records, with a drop signal | None; the supplier drops Firmbatch when latency traffic arrives | Opportunistic only; a permitted fast lane that never passes Business Gate 2 |
| Completion hedge | Not applicable; purchased on ordinary firm terms | GPU-seconds | Firm purchase from a job's capped hedge budget | Outside the residual contract and operator RFQ |

`supply_class` on an execution is one of `opportunistic`, `accepted_honoured`, `accepted_revoked`, `purchased`, `endpoint`, `hedge`; delivery-valid work is tagged as it is produced, and only `accepted_honoured` earns the step-up. `usage_basis` is `gpu_seconds` on everything but the endpoint class, where it is `requests`; the delivery-valid ledger keys on the basis, so an endpoint supplier's statement lists accepted requests and their revenue, never hours it does not have. **[rev D]**

**Endpoint metering, defined since D.1.** Execution accounting on endpoint supply is **per request**, from the supplier's own usage records, with **raw input and output token meters stored beside it** whenever the supplier reports them, as evidence. The contract's **pricing unit** — a share of NCR or a per-token price — is a **frozen term on the attempt**, like `share_bps`; which unit a given supplier quotes is that supplier's answer to the endpoint RFQ. A delivery-valid request is one whose response passed structural validation, and an accepted unit is one the customer's policy accepted, attributed per request exactly as on GPU supply. No GPU-hours are ever fabricated for an endpoint supplier, and delivery-valid work and customer acceptance are not collapsed there either. **[D.1]**

The premium vests only on an honoured window. Operator revocation inside an accepted window returns eligible completed work to the ordinary share and carries nothing forward. An unfilled nomination costs Firmbatch no cash — 25% of zero is zero — so eligibility gating exists to protect the supplier from nominating capacity Firmbatch cannot route, not to protect Firmbatch's cash.

## 13. Window admission and routing

### 13.1 Minimum worthwhile window

```text
W_min = (L_load + E[tail] + L_other) / (1 - eta_min)
```

- `L_load`: time to make the model resident.
- `E[tail]`: expected residual of the in-flight microbatch when the window ends.
- `L_other`: lease acquisition, input fetch, and manifest-write overhead.
- `eta_min`: lowest acceptable delivery efficiency for that window.

Illustrative values from the target; the four large-model rows are planning figures, not measurements: **[rev D]**

| Case | `L_load` | `E[tail]` | `L_other` | `eta_min` | `W_min` |
| --- | ---: | ---: | ---: | ---: | ---: |
| Artifact cache persists on node | 45 s | 60 s | 0 | 0.80 | 8.8 min |
| Same, lower efficiency accepted | 45 s | 60 s | 0 | 0.70 | 5.8 min |
| Same, plus per-window overhead | 45 s | 60 s | 60 s | 0.80 | 13.8 min |
| No cache; model pulled each time | 8 min | 60 s | 0 | 0.80 | 45.0 min |
| Frontier single card (~170 GB) from a local NVMe cache **[rev D]** | 2 min | 60 s | 0 | 0.80 | 15 min |
| Same, weights pulled from object storage at ~1 GB/s **[rev D]** | 3.5 min | 60 s | 0 | 0.80 | 22.5 min |
| Frontier node (~1.4 TB, 8 GPUs) from local NVMe at ~2 GB/s **[rev D]** | 12 min | 60 s | 0 | 0.80 | 65 min |
| Same, from object storage at ~1 GB/s **[rev D]** | 24 min | 60 s | 0 | 0.80 | 125 min |

Without a persistent artifact cache a window must be several times longer before it is worth entering, and most residual windows are not. Artifact-cache persistence and the distribution of free-window lengths by GPU class and region are central operator qualification data. On the frontier lane a persistent local copy of the weights is a precondition rather than a preference, a preempted node costs an hour of loading rather than a minute, and short spot windows are useless to it — which is why that lane is Phase B.

### 13.2 Expected value per job and placement

A static per-provider reliability score is insufficient because variance and tail behavior determine whether a placement can satisfy a particular job.

For candidate placement `i`:

```text
E[V_i] = expected delivery-valid work for this job on placement i
```

The expectation is conditioned on shard size, model residency, region policy, and remaining deadline slack. Deadline-bearing work routes using a low quantile of the distribution; slack flex work may route on the mean. Commit granularity — commit interval, notice, re-imaging — is a per-provider property that enters `E[tail]`, and therefore both `W_min` and `E[V_i]`; it is an input, not a separate reliability adjective. The measured notice is what enters.

### 13.3 Cost in routing, and measured throughput **[rev D]**

`E[V]` is right for shared capacity, whose hours cost Firmbatch nothing. On purchased capacity the router scores expected delivery-valid work **per dollar**:

```text
score_i = E[V_i] / cost_i        cost_i = purchase_rate / eta_delivery + egress the placement implies
```

with the price register as its input and the rate snapshotted on the purchase. When shared and purchased capacity both exist, shared goes first. The source's motivating example is the same H100 costing several times more in one region than another on the same day; a router without a cost term would be indifferent between a bridge that clears every job shape and one that clears none. Admission applies the shape rule to purchased placements. Units in every cost-versus-value comparison must match, and the decision, the cost and measurement versions and the reason are persisted.

The certification registry (§3.1) is a routing gate keyed by model digest, runtime image digest, runtime version, precision, GPU class, GPU count and parallelism, provider and region, and is global. Since rev D it also holds the profile's **measured** prefill and decode throughput and its `W_min` inputs (load time with and without a cache), because the planner's shard sizing and every quote depend on a number Gate 1 produces rather than a placeholder tokens-per-second figure. Paid admission depends on measured certification; an unmeasured profile is not certified for customers by fiat, and the measurement comes from qualification jobs (§5.5).

### 13.4 Multi-GPU executions **[rev D]**

`execution_spec` carries `gpu_count`, the parallelism (tensor, expert) and the node class, and the certification registry is keyed on them, so a profile certified on one H100 says nothing about the same model on eight of a larger card. v1 runs single cards. Node executions exist for two reasons — whole-node residual nominated under T8, and the frontier lane, where a model of roughly 280 billion parameters fits one large card and one of 2.8 trillion needs a node — and both are Phase B. Schema capacity to describe a node is not multi-GPU support.

## 14. AWS deployment shape

| Layer | Choice | Required property |
| --- | --- | --- |
| Edge | ALB with TLS | TLS termination and routing for the metadata-only job API |
| Compute | ECS Fargate; one image, services for API, controller/reconciler, validator/canonicalizer | Provider credentials isolated with controller; validator parses untrusted output without provider keys |
| State | RDS PostgreSQL with automated backups and point-in-time recovery | Only metadata authority; tenant ownership explicit |
| Payload | S3 with versioning, lifecycle, tenant-scoped prefixes, and KMS | Immutable attempt prefixes; presigned customer access; a bucket per supplier cloud region is the egress mitigation, not the v1 default |
| Workers **[rev D]** | The signed worker image on rented spot VMs in three clouds and at Verda; on operators' clusters from Phase P | The image is the same everywhere; only the driver and the credentials differ |
| Messaging | SQS plus transactional outbox | Wake-up only; duplication or loss cannot corrupt state |
| Secrets | Secrets Manager and KMS; one-time worker registration to short-lived scoped tokens; one least-privilege service account per cloud and per supplier account | Shared `FB_TOKEN` removed; a Gate 2 precondition, not hygiene |
| Observability | CloudWatch and OpenTelemetry; structured metadata-only logs; measurement records in PostgreSQL | Automated log scans test for payload and secret leakage; Gate 1's numbers are rows, not log lines |
| Delivery | Terraform modules, isolated test and production, CI/CD with explicit migration step | Reproducible and auditable deployment |

The target estimates roughly $115 per month per environment for the base AWS shape, with the NAT gateway accounting for roughly one third. This is a planning estimate and must be refreshed before a purchasing decision.

AWS hosts the control plane and the initial payload plane; GPU execution is multi-cloud. The two decisions are separate: a customer can see the portal long before a GPU provider is qualified. The roadmap pulls a protected staging subset of this shape forward to Milestone 3.3; deploying it remains planned and needs a reviewed infrastructure plan, a cost estimate and explicit authorization.

## 15. v1 scope boundary

### 15.1 Enabled in v1

Phase 0 enables:

- Native Firmbatch Job API.
- Python SDK and CLI.
- OpenAI-style request bodies inside JSONL where applicable.
- The evaluation tier and its report. **[rev D]**
- The internal qualification tier, never customer-visible. **[D.1]**
- 72-hour flex tier.
- General text-generation batch on certified open-weight profiles.
- Drivers for Google, Azure and AWS spot and for Verda. **[rev D]**
- The bridge envelope, purchase records and measurement records. **[rev D]**
- Declarative acceptance policies.
- Accepted-unit accounting, a per-request ledger and the customer invoice.
- Hard spend envelopes.
- Interruption recovery.

### 15.2 Built but dark

- **The firm tier** — a customer-named deadline of at least 24 hours and under 72, from Phase B — has schema, contract fields, hedge budget and credit policy behind a release flag. It turns on when the same workload has survived measured provider loss and cross-provider recovery: a release gate, not an architecture change. The previous "24-hour firm tier" wording is superseded. **[rev D]**
- **Window offers, acceptance and revocation, the nominated classes and the operator statement** — exercised end to end in test against the canon's rules, dark until a supplier signs or exposes a capacity endpoint. **[rev D]**

"Built but dark" is a required future release state, not a claim that today's repository has it.

### 15.3 Explicitly not built in v1

- The operator capacity agent (Phase P). **[rev D]**
- Two-sided settlement statements in production (Phase P). **[rev D]**
- The router across operators (Phase P). **[rev D]**
- The endpoint adapter — when an endpoint supplier signs. **[rev D]**
- Multi-GPU executions and the frontier lane (Phase B). **[rev D]**
- Optional OpenAI Batch translation adapter.
- Fragment harvesting.
- Yield pricing.
- Calibrated forecasting.
- Statistical quality certification.
- Customer-supplied validator containers.
- Training.
- Embeddings.
- Multimodal inference.

### 15.4 Phase triggers **[rev D]**

| Phase | Trigger | What turns on |
| --- | --- | --- |
| Phase 0 | Business plan v3.4's purchased-capacity launch; Milestone 8's release gate | Everything in §15.1, on qualified single-GPU profiles under approved caps |
| Phase P | A supplier signs approved terms and provides capacity visibility (agent or equivalent endpoint) | Nomination and settlement paths, the agent, production operator statements, routing across operators; eligible purchased work marked `movable_to_shared` migrates job by job |
| Endpoint extension | An endpoint supplier signs, with drop signals and usage evidence | The endpoint adapter under per-request accounting; never Gate 2 proof |
| Phase B | Whole-node and multi-GPU certification; the firm release gate | Node windows, the frontier lane, firm-tier activation |

The business gates run 0 → 1 → 3 → 2 (plan v3.4 §5): census, qualification on bought capacity, paying customers, then the supplier signature triggered by the second paying customer. Neither purchased spot nor an endpoint arrangement is evidence that Business Gate 2 passed; Gate 1's protocol is stated in §8.3 and its thresholds are the plan's.

## 16. Costs made explicit

1. **S3 egress to providers.** Record current regional transfer rates in the price register. Retries pay egress again, so cost scales with interruption rate as well as volume. Co-locate the primary bucket and pool and use persistent execution caches where possible.
2. **Cross-cloud egress on the bridge.** **[rev D]** The payload plane is on S3 and Phase 0's workers run in other clouds, so input-heavy jobs pay cross-cloud egress on every input fetch and every re-run. The mitigation is a bucket per supplier cloud region behind the same presigned-URL interface, adopted when the bridge's egress bill says so.
3. **The bridge cost itself.** **[rev D]** Purchased capacity costs `purchase_rate / eta_delivery + o_ctrl` per delivery-valid hour, reported against the envelope monthly and weekly. The source's figures are illustrations; the actual number is a measurement.
4. **Acceptance gap.** Firmbatch may pay for delivery-valid work that the customer's policy rejects. Under Structure A the supplier shares it proportionally; under Structure B Firmbatch absorbs it up to the floor; on purchased capacity Firmbatch absorbs all of it. It is a different number in each case and is reported either way; it is invisible if the ledgers are collapsed.
5. **The hedge premium.** The only line that may pay for availability rather than output. Capped inside an admitted job's envelope and priced into its quote. Hedge liquidity is thinnest where region policy is tightest.
6. **Isolation over density.** One tenant per execution means small jobs cannot share a card — or, on the frontier lane, a node. The utilization cost is deliberate and belongs in pricing.
7. **Firmbatch's own redundancy.** **[rev D]** Under Structure B a losing duplicate attempt is still paid for; on purchased capacity it is paid for twice. Deliberate: it prices duplication honestly.

## 17. Non-negotiable implementation invariants

The following condensed invariants are the acceptance criteria carried into implementation. Invariants 1–11 are unchanged from revision C and are cited by number in `AGENTS.md`, the `milestone` skill and ADRs 0004–0008; 12 and 13 are appended by revisions D and D.1.

1. PostgreSQL is authoritative; queues and providers are reconciled observations.
2. Every tenant-owned row, credential, and object key is tenant-scoped.
3. Customer payload bytes never pass through the API process or PostgreSQL.
4. Attempts and their output prefixes are immutable and fenced by monotonic lease generations.
5. A stale worker cannot heartbeat, publish, validate, canonicalize, or settle a newer attempt.
6. Only the validator/canonicalizer can promote one canonical result per request.
7. Accepted quotes and frozen commercial terms cannot be mutated retroactively.
8. Simultaneous and cumulative spend limits are enforced from the admitted envelope.
9. Provider execution, delivery-valid work, and customer-accepted units remain separate records.
10. Cancellation and settlement use closed, evidence-based causes and frozen terms.
11. Customer, internal operator, and supplier permissions and interfaces remain separate.
12. **[rev D, D.1]** No purchase is launched without an admitted job, and none outside the platform bridge envelope, whose caps are enforced as gross accrued spend with reservations, usage replacement and invoice reconciliation, and whose breach refuses the launch at admission. `purchase_rate` and `supplier_account` are frozen on every purchased execution, and a purchase record is never recomputed from a later price. Evaluation and qualification jobs spend the bridge under their own caps and are counted against it gross. No speculative duplication: a second attempt on a request is launched only after the first is confirmed lost or the deadline forecast breaches.
13. **[rev D, D.1]** `provider_policy` is a customer-stated exclusion of a provider class or named subprocessor that constrains **execution placement only** — first placement, every retry, every move to shared capacity and every hedge — and in v1 does not govern the payload plane; it never selects a placement, it never grants a customer any view of or control over supplier capacity, pool identities, bridge budgets or operator settlement, and its enforced scope is what the customer is told and nothing more. Invariant 11 is not weakened by it.

Rev D's note on itself: every rule in this list was in rev C but invariant 12, and that one exists because money now leaves the company by the hour before a supplier has signed.

## 18. Revision record **[rev D]** **[D.1]**

Rev B replaced the OpenAI-compatible customer edge with a native, provider-independent job API. Rev C resolved the settlement contradiction (a revenue share and "no acceptance risk" cannot both hold), split supply into classes with different accounting, and made window admission and routing explicit; rev C.1 added the operator capacity agent as a third deployable artifact, the three ledgers named separately, the commercial fields frozen on every attempt, the window state machine, and a cause enum with an asserting party.

**Rev C → rev D, by section of this document:**

| Section | Change |
| --- | --- |
| Header, intro | Source is the rev D PDF and Markdown; snapshot and hashes; `[rev D]` markers; Phase 0 / P / B vocabulary |
| §1 | Usage basis; the abstraction is the product across three clouds |
| §2 | Two of the three artifacts in Phase 0; agent is Phase P |
| §2.1 | Evaluation tier, `auto_accept_below`, measured-throughput planner, shape rule and bridge cap at admission, `E[V]` per dollar, purchase-record reconciliation, measurement writes, evaluation report |
| §3.1 | Bridge envelope, purchase records, per-usage-basis ledger, measurement records, registry throughput, price register |
| §3.3 | Bucket per supplier cloud region as egress mitigation |
| §4.1–4.3 | Node-class isolation cost; agent Phase P and API-only suppliers; purchased-spot and endpoint execution classes |
| §4.4 | New: the Phase 0 spot drivers |
| §5.1 | `uploaded`; evaluation lifecycle |
| §5.2–5.4 | `provider_policy`, `auto_accept_below`, `service_tier = evaluation`; new §5.3 and §5.4 |
| §6 | Purchased column; `eta_delivery` as a cost |
| §7 | Purchased-spot column; T8/T9; a create attempt is a purchase |
| §8 | Evaluation cap; new §8.1 bridge envelope, §8.2 purchase records, §8.3 measurement records |
| §9 | Unchanged formulas; `f = 0` on purchased and endpoint; new §9.4 |
| §10 | `usage_basis`, `delivery_valid_requests`, `supplier_account`, `purchase_rate`; purchased column |
| §11 | Cloud as asserting party on purchased spot; reroute and envelope evidence widened |
| §12 | Node unit, GPU count and topology in the acceptance snapshot; T8/T9; purchased and endpoint classes; `supply_class` and `usage_basis` enums |
| §13 | Frontier `W_min` rows; new §13.3 cost in routing and measured throughput; new §13.4 multi-GPU |
| §14 | Workers row; secrets and observability notes; hosting separate from supply; staging pointer |
| §15 | Phase 0 enablement list; firm tier redefined; windows and statements dark; agent, statements, cross-operator router, endpoint adapter and frontier lane not built; new §15.4 phase triggers |
| §16 | Cross-cloud egress, bridge cost, hedge premium, own redundancy |
| §17 | Invariants 1–11 verbatim; 12 and 13 appended |

**Rev D → rev D.1, by section — the ten review items resolved and the qualification tier added** (each entry's source authority is in the review register):

| Section | Change |
| --- | --- |
| Header, intro | Source is the rev D.1 PDF and Markdown; both snapshots kept; `[D.1]` markers; no open rules carried |
| §3.1 | The price register named: `gpu_price_register_1.xlsx` r1 with captured dates (D5, D9 inputs) |
| §3.3 | The payload plane is S3 for every tenant until a bucket per supplier cloud exists (D8) |
| §5.2 | `service_tier` gains `qualification` |
| §5.3 | Evaluation rules: one per tenant per corpus, 1,000 requests, token and spend caps in the envelope, the report always produced, `x` per roadmap r2_4 D4, no self-conversion (D7) |
| §5.4 | `auto_accept_below`: quote always stored; total excluding VAT and payment fees in the billing currency, less than or equal; consent bound to the submitting credential, recorded on the quote, lapsing at expiry (D7). `provider_policy`: execution placement only, not the payload plane; a customer excluding Amazon cannot be served in v1 (D8) |
| §5.5 | New: the internal qualification tier |
| §6 | `eta_realisation` named beside the two efficiencies |
| §8.1 | The plan's $3–5k monthly and $10k total as a planning range; gross accrued enforcement with reservations, usage replacement and invoice reconciliation; net-of-invoiced reporting in USD at the ECB rate; refusal at admission; numeric retirement; weekly reporting; configured caps left to a human (D5) |
| §8.2 | Immutable launch snapshot; append-only usage, rate intervals and invoice adjustments; past cost never recomputed (D9) |
| §8.3 | Gate 1's seven-day per-pool, per-zone protocol and its pass and fail thresholds, owned by the plan (D6) |
| §9.3 | Grouping once per operator-month with per-class as a contract parameter; the 90-day true-up and the two-clock settlement timing (D3) |
| §9.4 | The canon's opening posture |
| §10.1 | Frozen terms and measured outcomes kept apart; the acceptance-policy version among the terms; the window outcome among the outcomes (D10) |
| §11 | `operator_platform_failure` (D1); revocation by `operator_reclaim`, `operator_blackout` and an operator-asserted `security_stop` (D2); `f_c` from RFQ Q5 |
| §12.2 | Endpoint metering per request with raw token meters as evidence and the pricing unit frozen on the attempt (D4) |
| §13.3 | Measurement comes from qualification jobs |
| §15.1, §15.4 | Qualification tier enabled internally; gate order 0 → 1 → 3 → 2 |
| §17 | Invariants 1–11 unchanged; 12 and 13 restated with D.1's rules |

**Unchanged by rev D and D.1:** the attempt / delivery-valid / accepted-unit split (§6), the three ledgers (§3.1), the settlement formulas and the once-per-month `max` (§9), the window state machine (§12.1), `W_min` and `E[V]` (§13.1–13.2), and §17 invariants 1–11.

**Choices the authorities leave open on purpose** (review register §3): the exact configured bridge caps and supplier sub-caps; the numeric per-evaluation token and spend caps; the quote validity duration; the corpus identity rule; the qualification tenant and allow-list; the per-contract settlement grouping; operator-quoted `f_c`; the endpoint pricing unit per supplier; the model band as a Gate 1 measurement outcome; Gate 1 threshold revisions, which are the plan's; the AWS staging authorisation; the agent language. None is a discrepancy between sources, none is fixed by this document, and none blocks Milestone 3.

**Companions reviewed:** `settlement-model-r1_3.md` (Amendment 4), plan v3.4, roadmap r2_4, `gpu_price_register_1.xlsx`, the customer brief r2, the definitions register r4, the demand-alternatives map r3, the operator's equation paper r2, RFQ r2 and the endpoint RFQ r1 — hashes and roles in `docs/architecture/sources/README.md`. They inform this document; they authorize nothing.
