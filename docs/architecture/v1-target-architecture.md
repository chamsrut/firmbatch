# Firmbatch v1 target architecture

**Status:** Canonical implementation specification after repository review
**Source:** `firmbatch_v1_target_architecture_3.pdf`
**Source revision:** C, 1 September 2026
**Scope:** Product and execution architecture; customer account and billing sequencing is defined in `docs/firmbatch-v1-roadmap.md`

This document is the version-controlled rendering of the approved Firmbatch v1 target architecture. It preserves the decisions in the source PDF in a format that can be reviewed, diffed, linked from code, and used by implementation agents.

The source architecture and this document define product behavior. They do not authorize infrastructure launches, provider spend, production changes, or external communication.

## 1. System intent

Firmbatch v1 is a multi-tenant, metadata-controlled batch execution service behind a native, provider-independent job API.

- The core operational unit is an immutable **attempt**.
- The commercial unit is an **accepted unit**: delivery-valid work that passes the customer's contracted acceptance policy.
- Every execution is assigned an explicit **supply class**.
- Firmbatch decides where and how a job executes; the customer specifies what is required and by when, never the provider.
- Customer payload bytes travel through the payload plane, not through the API or PostgreSQL.

## 2. Deployable artifacts and implementation boundaries

The target has three deployable artifacts:

1. **Control plane:** one Python image, run in three service roles.
2. **Operator capacity agent:** one static Rust or Go binary installed in an operator's cluster.
3. **Execution worker:** a signed, digest-pinned OCI image.

The architecture does not require Firmbatch-authored C++. The execution image may contain upstream native/CUDA components required by the inference engine, but a custom C++ inference runtime is not a v1 requirement.

### 2.1 Control-plane roles

The three roles share a Python image but run with separate processes, permissions, and responsibilities.

#### Role 1: API

Responsibilities:

- Authentication and tenancy: an API credential resolves to `tenant_id`; scopes apply to every tenant-owned row and S3 key.
- Idempotency: every mutating call takes an idempotency key; a retried request cannot create a second job or repeat a state change.
- Job lifecycle, quote issuance, and quote acceptance.
- Presigned upload and download access. Payload bytes never enter the API process.

Representative native endpoints:

```text
POST /v1/jobs
POST /v1/jobs/{id}/submit
POST /v1/jobs/{id}/accept-quote
GET  /v1/jobs/{id}
POST /v1/jobs/{id}/cancel
GET  /v1/jobs/{id}/results
```

#### Role 2: Controller and reconciler

Responsibilities:

- Provider drivers: quote, capacity, launch an execution specification, observe, cancel, usage, reconcile, and offer/accept/revoke windows.
- Planner: token-estimated shards, not row-count shards.
- Admission:
  - Flex work is admitted on expected value and statistical capacity.
  - Firm work is admitted on coverage, probability of finish, and region-eligible hedge capacity.
- Router: evaluates `W_min` and expected delivery-valid value for each job using certified profiles only; every routing choice records its reason.
- Reconciler: compares Firmbatch state with provider truth; records cause and actor; applies the contractual settlement grouping.

Provider credentials live with this role, not with the API, validator, canonicalizer, or workers.

#### Role 3: Validator and canonicalizer

Responsibilities:

- Validator: structural checks and delivery-valid classification, including the attribution key and the Structure B floor basis. Acceptance policy determines accepted and billed units.
- Canonicalizer: produces one delivery-valid result per request. Requests in one shard may be won by different attempts. Holds no provider keys.

Only this role may promote attempt-scoped output into customer-visible canonical results.

## 3. Core infrastructure

### 3.1 PostgreSQL: the single authority

PostgreSQL is authoritative for all Firmbatch metadata, contracts, state transitions, decisions, and ledgers, including:

- Tenants, credentials, quotas, jobs, and quotes.
- Per-job and per-tenant spend envelopes.
- Shards, attempts, leases, and fencing tokens.
- Provider-execution ledger: capacity consumed.
- Delivery-valid ledger: attributable delivery-valid hours by operator.
- Revenue and acceptance ledger: the canonical attempt and customer-accepted units.
- Settlement periods and statements.
- Window offers.
- Global certification registry.
- Routing and admission decisions.

Every role reads and writes PostgreSQL. Every tenant-owned authoritative row carries `tenant_id`; shared provider and certification records are explicitly global.

### 3.2 Transactional outbox and SQS

State changes and their events are written in one database transaction through a transactional outbox. SQS is a wake-up mechanism only and is never authoritative. Losing or duplicating a message must not corrupt state.

### 3.3 S3 payload plane

- Inputs and manifests are immutable.
- Output prefixes are attempt-scoped.
- A retry never overwrites another attempt.
- Canonical results use tenant-scoped keys.
- Customers access objects only through presigned URLs.
- Payload bytes do not pass through the API, queues, logs, or PostgreSQL.

## 4. Security and execution plane

### 4.1 Execution security domain

An execution security domain is:

```text
tenant_id + model-artifact classification + region
```

In v1, one execution never concurrently serves two tenants. This deliberately trades packing density for isolation; the utilization cost belongs in the cost model.

### 4.2 Operator capacity agent

The operator capacity agent runs in the operator's cluster and:

- Reads scheduler state.
- Emits signed availability envelopes, window offers, and reclaim events.
- Uses outbound-only communication.
- Receives no customer payload.
- Holds no long-lived Firmbatch credential.
- Uses rate-limited, narrowly scoped credentials.
- Treats offers as inputs only: Firmbatch acceptance creates an obligation; a compromised or broken agent cannot invent a payable.

### 4.3 Execution classes

Supply class belongs to an execution, not permanently to a provider.

- **Verda — VM execution:** one execution may serve many attempts. Spot, evictable opportunistic supply is available without an agent; nominated supply requires the capacity agent.
- **Lyceum — serverless execution:** one execution is bound to one attempt and is vendor-managed. It is opportunistic only and cannot offer nomination windows.
- **Embedded operator pool — later:** long-lived lowest-priority pods, agent installed by default, supporting opportunistic and nominated windows.

## 5. Job lifecycle and customer contract

### 5.1 Lifecycle

```text
draft -> uploading -> validating -> quoted
      -> admitted -> running -> finalizing
      -> completed | partial | failed | cancelled
```

Transitions are explicit and persisted. Quote issuance and acceptance are contractual events. An accepted quote is immutable.

### 5.2 Canonical JobSpec

There is deliberately no provider field.

```json
{
  "input": { "format": "jsonl" },
  "model": {
    "id": "Qwen/Qwen3-8B-Instruct",
    "runtime_profile": "vllm-bf16"
  },
  "service_tier": "flex",
  "deadline": "2026-09-03T18:00:00Z",
  "acceptance_policy": { "id": "policy_17", "version": 3 },
  "region_policy": ["EU"],
  "output": { "format": "jsonl" },
  "idempotency_key": "customer-run-482"
}
```

Firmbatch chooses the provider, GPU class, and execution time. The customer expresses **what** is required and **by when**, never where it runs.

The JSONL input may contain OpenAI-style request bodies such as messages, temperature, maximum output tokens, and response format. This compatibility is inside each request; the enclosing job contract remains native to Firmbatch.

The source architecture identifies `auto_accept_below` as a useful optional future JobSpec field. It is not part of the required v1 contract until separately accepted. If added, the quote remains contractual and immutable while eligible repeat or automated jobs can complete submission without a second round trip.

## 6. Three accounting records

The following records are separate because they answer different commercial and operational questions.

| Record | Granted when | Pays or bills | Reason it stands alone |
| --- | --- | --- | --- |
| Provider execution work | Capacity was consumed, regardless of output quality | What Firmbatch owes the provider or operator | Compute consumption is a billing fact, not a quality fact. |
| Delivery-valid work | Output is structurally valid, attributable, complete, and correctly fenced | Attribution key for each accepted unit; basis of the Structure B floor | Identifies which operator produced shipped work; it is not itself the payment base under pure revenue share. |
| Customer-accepted units | Output passes the versioned acceptance policy frozen at admission | What the customer is charged for and therefore the revenue-share basis | Separates product acceptance from execution and delivery quality. |

Engineering delivery efficiency:

```text
eta_delivery = delivery-valid attributed work / provider execution work
```

Product acceptance efficiency:

```text
eta_accept = customer-accepted units / delivery-valid units
```

Collapsing these ratios hides whether a bad period came from failed capacity or rejected output. Neither ratio alone is an operator payment base.

## 7. Provider contract

The provider abstraction is execution-centric, not worker-centric.

| Call | Verda VM | Lyceum serverless | Embedded pool, later |
| --- | --- | --- | --- |
| `quote / capacity` | Spot price and availability by region and GPU class | Vendor quotas, queue time, and execution-start latency; capacity may be unknown | Operator-declared SKUs, caps, and blackout windows |
| `publish_availability_envelope` | Standing shape of what may become available, not a commitment | Not offered; capacity is opaque | Operator's residual view by SKU and region |
| `offer_window / accept_window / revoke_window(cause, at)` | Requires capacity agent or operator-side capacity endpoint; API-only pilot is opportunistic only | Not supported; opportunistic only | Operator offers; Firmbatch accepts only against admitted or forecast work; no unused reservation |
| `launch(execution_spec)` | One VM execution can serve many attempts | One execution is bound to one attempt | Long-lived lowest-priority pod serves many attempts |
| `observe / cancel` | Poll instance state; delete instance | Poll invocation; cancel invocation | Pod status; yield within contracted grace |
| `usage / reconcile` | Billed increments and orphan detection | Billed seconds and duplicate-invocation detection | Claimed, delivery-valid, and attributed-revenue hours, with a cause on every cancellation |

A nomination is two-sided. Separate offer, accept, and revoke actions must identify who moved and establish separate liabilities.

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
- Per-tenant aggregate envelope across jobs.

Concurrency caps alone are insufficient because a defective controller could repeatedly launch billable executions. The hedge budget is the only budget line that may pay for availability rather than output. It exists inside an admitted job's capped envelope and is priced into its quote; capacity is never bought speculatively.

## 9. Settlement

Net Collected Revenue (NCR) is cash collected for accepted units, less refunds and credits for those units, payment fees, and transaction taxes.

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

- `s_u` is the share frozen on a unit's canonical attempt.
- `f_a` is the floor rate frozen on an attempt.
- `h_a` is delivery-valid GPU-hours attributable to the attempt.
- `C_m` is the cancellation credit for the period.

The `max` is taken once across the whole operator-month and all supply classes together, unless a contract explicitly chooses the documented per-class fallback. It is not taken per hour or per class by default. Never add floor and share; doing so pays twice for the same production.

The cancellation credit sits outside the `max`. It is charged per payable cancelled GPU-hour from the last committed result to termination so it cannot overlap delivery-valid hours already in the floor leg. Structure A is the `f_a = 0` case of the same reconciler.

Revenue per delivery-valid GPU-hour is measured, not derived:

```text
R_c = NCR / delivery-valid GPU-hours
```

It is not generally equal to acceptance ratio multiplied by a uniform contract rate because units may carry different revenue and compute.

Collections received within 90 days after a settlement month closes are trued up in the next statement. Nothing is clawed back if an invoice is never collected; under Structure A the share of zero is already zero.

## 10. Attempt ledger and settlement cases

### 10.1 Fields frozen on every attempt

```text
operator_id
contract_version
supply_class
window_offer_id
share_bps
floor_rate
delivery_valid_gpu_seconds
cancellation_cause
cancellation_actor
```

These commercial snapshots are immutable once written. `supply_class` belongs to the execution and can vary for the same provider.

### 10.2 Required settlement behavior

| Event | Structure A | Structure B | Required ledger record |
| --- | --- | --- | --- |
| Delivered, accepted, paid | Supply-class share rate times NCR | Greater of floor leg or share leg, compared once for the month | `(job, request) -> canonical attempt -> operator`, acceptance status, and policy version |
| Delivery-valid, rejected by customer policy | Nothing | Hours enter the floor leg | Delivery-valid hours with policy ID and version frozen at admission |
| Delivery-valid, loses canonicalization to sibling | Nothing | Hours enter the floor leg | Both attempts and the winning attempt |
| Accepted, collected after month close | True-up in next statement within 90 days | Same, after the floor comparison already made | Collection date and settlement month |
| Accepted but never collected | Nothing | Hours remain in the floor leg | Invoice collection state, recorded per invoice |
| Operator reclaims before valid output | Nothing | Nothing | Reclaim signal, notice, and lost work |
| Firmbatch-caused cancellation | Credit at quoted rate | Credit at quoted rate | One cause from the closed cancellation enum |
| Unexplained termination | Credit at quoted rate | Credit at quoted rate | `unattributed`; instrumentation failure is charged to the party able to fix it |

## 11. Cancellation causes

Cancellation cause is a closed enum. Every cause is decidable from evidence visible to both sides rather than inferred intent. Adding a cause is a contract amendment, not an ordinary code change.

| Cause | Asserted by | Evidence | Execution payable | Revokes accepted window |
| --- | --- | --- | --- | --- |
| `operator_reclaim` | Operator | Reclaim signal in operator records at or before termination | No | Yes; window drops to base share |
| `operator_blackout` | Operator | Termination inside a declared blackout window or cap | No | Yes |
| `operator_platform_failure` | Operator | Node, network, or hypervisor failure in platform records | No | No; nobody chose it |
| `firmbatch_reroute` | Firmbatch | Deliberate replacement recorded in routing decision | Yes | No |
| `firmbatch_routing_error` | Firmbatch | Mis-routed, mis-certified, or misconfigured by Firmbatch | Yes | No |
| `firmbatch_envelope` | Firmbatch | Spend envelope or wall-clock kill-by reached | Yes | No |
| `firmbatch_sibling_won` | Firmbatch | Another attempt promoted for the same requests | Yes | No |
| `firmbatch_deadline_abandoned` | Firmbatch | Job stopped because it could no longer finish in time | Yes | No |
| `customer_cancelled` | Customer | Accepted customer cancellation with timestamp | Yes | No |
| `lease_expiry` | Neither | Lease expired with no reclaim signal and no platform failure | Yes | No |
| `security_stop` | Either; actor decides | Image-digest mismatch, credential revocation, or isolation violation | Firmbatch stop: yes; operator stop: no | Operator-asserted: yes |
| `unattributed` | Neither | Execution ended and neither side can explain it | Yes | No |

## 12. Window offers and supply classes

### 12.1 Window-offer state machine

```text
offered -> accepted -> active -> honoured
    |                    `----> revoked
    +----> rejected
    `----> expired
```

Acceptance, not offer, is the commercial event. Rejected and expired offers cost neither party. Only an honoured window earns the premium. If Firmbatch accepts a window and fails to fill it, the window can still be honoured; Firmbatch chose the risk.

Acceptance snapshots:

- Certified GPU class and runtime profile.
- Region.
- Capacity count.
- Start and expiry.
- Minimum usable window.
- Notice period.
- Required cache state.
- Share step-up in basis points.
- Contract version.

Eligibility is evaluated once against the offered terms and then frozen.

### 12.2 Supply classes

| Class | Share of NCR | Commitments | Routing consequence |
| --- | --- | --- | --- |
| Opportunistic residual | 20% | Neither side commits | Default; router takes available residual capacity |
| Accepted nomination | 25% | Operator offers; Firmbatch explicitly accepts only against admitted or forecast work | Admit only if `W >= W_min`, profile is certified, and region is permitted |
| Accepted nomination, stronger terms | 30% | Binding notice, certified profile, permitted region, persistent artifact cache, completion distribution above threshold | Eligible for deadline-bearing work; still admitted on job-specific expected value |
| Completion hedge | Not applicable; purchased on ordinary firm terms | Firm purchase from a job's capped hedge budget | Outside the residual contract and operator RFQ |

The premium vests only on an honoured window. Operator revocation inside an accepted window returns eligible completed work to the ordinary share and carries nothing forward.

## 13. Window admission and routing

### 13.1 Minimum worthwhile window

```text
W_min = (L_load + E[tail] + L_other) / (1 - eta_min)
```

- `L_load`: time to make the model resident.
- `E[tail]`: expected residual of the in-flight microbatch when the window ends.
- `L_other`: lease acquisition, input fetch, and manifest-write overhead.
- `eta_min`: lowest acceptable delivery efficiency for that window.

Illustrative values from the target:

| Case | `L_load` | `E[tail]` | `L_other` | `eta_min` | `W_min` |
| --- | ---: | ---: | ---: | ---: | ---: |
| Artifact cache persists on node | 45 s | 60 s | 0 | 0.80 | 8.8 min |
| Same, lower efficiency accepted | 45 s | 60 s | 0 | 0.70 | 5.8 min |
| Same, plus per-window overhead | 45 s | 60 s | 60 s | 0.80 | 13.8 min |
| No cache; model pulled each time | 8 min | 60 s | 0 | 0.80 | 45.0 min |

Artifact-cache persistence and the distribution of free-window lengths by GPU class and region are central operator qualification data.

### 13.2 Expected value per job and placement

A static per-provider reliability score is insufficient because variance and tail behavior determine whether a placement can satisfy a particular job.

For candidate placement `i`:

```text
E[V_i] = expected delivery-valid work for this job on placement i
```

The expectation is conditioned on shard size, model residency, region policy, and remaining deadline slack. Deadline-bearing work routes using a low quantile of the distribution; slack flex work may route on the mean. Commit granularity enters `E[tail]`, and therefore both `W_min` and `E[V_i]`.

## 14. AWS deployment shape

| Layer | Choice | Required property |
| --- | --- | --- |
| Edge | ALB with TLS | TLS termination and routing for the metadata-only job API |
| Compute | ECS Fargate; one image, services for API, controller/reconciler, validator/canonicalizer | Provider credentials isolated with controller; validator parses untrusted output without provider keys |
| State | RDS PostgreSQL with automated backups and point-in-time recovery | Only metadata authority; tenant ownership explicit |
| Payload | S3 with versioning, lifecycle, tenant-scoped prefixes, and KMS | Immutable attempt prefixes; presigned customer access |
| Messaging | SQS plus transactional outbox | Wake-up only; duplication or loss cannot corrupt state |
| Secrets | Secrets Manager and KMS; one-time worker registration to short-lived scoped tokens | Shared `FB_TOKEN` removed |
| Observability | CloudWatch and OpenTelemetry; structured metadata-only logs | Automated log scans test for payload and secret leakage |
| Delivery | Terraform modules, isolated test and production, CI/CD with explicit migration step | Reproducible and auditable deployment |

The target estimates roughly $115 per month per environment for the base AWS shape, with the NAT gateway accounting for roughly one third. This is a planning estimate and must be refreshed before a purchasing decision.

## 15. v1 scope boundary

### 15.1 Enabled in v1

- Native Firmbatch Job API.
- Python SDK and CLI.
- OpenAI-style request bodies inside JSONL where applicable.
- General text-generation batch on registered open-weight models.
- 72-hour flex tier.
- Verda and Lyceum.
- Declarative acceptance policies.
- Accepted-unit accounting.
- Hard spend envelopes.
- Interruption recovery.

### 15.2 Built but dark

The 24-hour firm tier has schema, contract fields, hedge budget, and credit policy behind a release flag. It is enabled only after the same workload survives measured provider loss and cross-provider recovery.

### 15.3 Explicitly not built in v1

- Optional OpenAI Batch translation adapter.
- Fragment harvesting.
- Yield pricing.
- Calibrated forecasting.
- Statistical quality certification.
- Customer-supplied validator containers.
- Training.
- Embeddings.
- Multimodal inference.

## 16. Costs made explicit

1. **S3 egress to providers.** Record current regional transfer rates in the provider cost book. Retries pay egress again, so cost scales with interruption rate as well as volume. Co-locate the primary bucket and pool and use persistent execution caches where possible.
2. **Acceptance gap.** Firmbatch may pay for delivery-valid work that the customer's policy rejects. This is the difference between `eta_delivery` and `eta_accept` and is invisible if the ledgers are collapsed.
3. **Isolation over density.** One tenant per execution means small jobs cannot share a card. The utilization cost is deliberate and belongs in pricing.

## 17. Non-negotiable implementation invariants

The following condensed invariants are the acceptance criteria carried into implementation:

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
