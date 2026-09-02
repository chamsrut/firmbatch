# Firmbatch v1: Pilot-Ready Product Specification and Build Roadmap

> [!WARNING]
> **Superseded on 2 September 2026. Do not execute this file as the current plan.**
>
> The active target is `docs/architecture/v1-target-architecture.md` and the active
> implementation sequence is `docs/firmbatch-v1-roadmap.md`. The content below is historical context.

## 1. Purpose

This document is the implementation roadmap from the existing Firmbatch v0 prototype to a
pilot-ready Firmbatch v1: a production service for deadline-guaranteed, general generative batch
inference across heterogeneous GPU supply.

It is designed to be used iteratively with GPT-5.6 and Claude. Each numbered milestone is a bounded
unit of progress with explicit deliverables, invariants, tests, and a completion gate. A milestone
may be split into several implementation prompts or pull requests, but it is complete only when its
entire gate passes.

There is deliberately no timeline. The milestone number is the progress tracker.

## 2. Pilot outcome

At the end of this roadmap, a customer can:

1. authenticate to Firmbatch as an isolated tenant;
2. upload an OpenAI-compatible JSONL batch without sending the payload through the control plane;
3. select a supported generative model and inference parameters;
4. request a completion deadline and receive an explicit quote;
5. accept the quote and submit the job;
6. have Firmbatch execute token-aware shards on certified GPU/runtime combinations across multiple
   supply pools;
7. survive worker loss, provider interruption, duplicated delivery, and partial output;
8. download a complete result and error file through presigned object-store URLs;
9. see the provenance and accounting record for every request; and
10. verify that the quoted price and promised deadline were met, or receive a precisely recorded
    service failure or credit.

The pilot must prove the commercial hypothesis, not merely that GPU containers can be launched:

> Firmbatch can offer a useful price/deadline trade-off by starting work on inexpensive,
> interruptible GPU capacity and escalating only when the probability of missing the deadline
> requires it.

## 3. Product boundary

### 3.1 Included in v1

- General text-generation batch inference for supported open-weight models.
- OpenAI-compatible file and batch concepts, with Firmbatch extensions for deadline, service class,
  quote, and quality profile.
- Multiple model families, selected from actual pilot demand.
- One primary inference engine, initially expected to be vLLM unless benchmarking disproves the
  choice.
- Multiple certified NVIDIA GPU types.
- At least two interruptible supply pools in separate failure domains.
- At least one physically credible firm or on-demand fallback path.
- Production tenant isolation, API authentication, quotas, audit events, encryption, observability,
  test and production environments, CI/CD, and infrastructure as code.
- Fixed-price or price-capped quotes derived from declared token limits and measured execution
  profiles.
- Per-request validity checking and fleet-level statistical quality certification.

### 3.2 Explicitly excluded from the pilot

- Arbitrary customer-supplied containers or arbitrary code execution.
- Arbitrary unreviewed Hugging Face models.
- Training, fine-tuning, embeddings, image generation, audio, and multimodal inference unless a
  signed pilot specifically requires one of them.
- A low-latency synchronous inference endpoint.
- Kubernetes unless a measured operational requirement makes it necessary.
- Multiple inference engines merely for breadth; the first engine should be deeply certified.
- A marketplace, customer-managed GPU nodes, or peer-to-peer supply.
- Full enterprise RBAC, SAML, SCIM, custom contracts, automated invoicing, or a polished billing
  portal.
- A semantic guarantee that generated text is factually or subjectively correct.

### 3.3 Meaning of “general generative inference”

“General” means that the API supports arbitrary customer text-generation requests and common
sampling parameters across a declared model catalogue. It does not mean that every model, runtime,
GPU, modality, or customer container is accepted.

The supported request surface should include, where the selected model/runtime supports it:

- chat messages or a text prompt;
- temperature, top-p, seed, stop sequences, and maximum output tokens;
- structured JSON output constraints;
- per-request `custom_id` values;
- model and quality-profile selection; and
- request-level metadata that is returned but never interpreted as scheduling authority.

## 4. Service contract

### 4.1 What Firmbatch guarantees

For an admitted job, Firmbatch promises to deliver the contracted proportion of **valid inference
responses** by the committed deadline, using a declared model and certified inference profile. If it
does not, the contract records the failure and applies the pilot’s agreed credit or refund rule.

The pilot must never describe a stochastic generated response as semantically “accepted” by the
infrastructure. Use these terms consistently:

- **Valid response:** passed per-request protocol and execution checks.
- **Invalid response:** malformed, corrupt, produced by the wrong profile, or ended in a disallowed
  runtime condition.
- **Accounted request:** has exactly one final valid response or one explicit terminal error.
- **Quality-conformant profile:** its aggregate behaviour passed the certification suite.
- **Completed job:** every input request is accounted for and the contracted valid-response target
  is satisfied.

### 4.2 Per-response validity

A valid response must have:

- the exact tenant, job, and `custom_id` association;
- a unique winning result;
- a schema-valid response and usage record;
- the contracted model artifact, tokenizer, runtime image, inference configuration, and quality
  profile;
- a permitted finish reason;
- no runtime error, NaN, corrupt token sequence, silent truncation, or checksum mismatch;
- input and output token counts that reconcile with the tokenizer/accounting implementation; and
- complete execution provenance.

Validity does not assert factual correctness, relevance, style, or customer satisfaction.

### 4.3 Fleet-level quality conformance

Quality is certified statistically for a complete execution profile, not judged independently for
each generated response. A profile includes:

`model artifact + tokenizer + runtime image + runtime arguments + precision/quantization + GPU SKU + driver/CUDA stack`

Only profiles that pass the certification policy may receive admitted customer work.

## 5. Non-negotiable system invariants

These invariants should appear in code comments, tests, architecture records, and prompt context.

1. **Postgres is the authority for contracts and state.** Queues, caches, and provider APIs are not
   authoritative.
2. **S3 is the payload data plane.** Customer input and output bodies do not pass through the API,
   scheduler, or Postgres.
3. **Receiving work is not owning work.** Ownership requires a conditional lease claim.
4. **Every lease has a monotonically increasing generation.** A stale worker cannot heartbeat,
   publish, validate, or settle a newer attempt.
5. **Attempt outputs are immutable.** Workers write only beneath an attempt-specific prefix.
6. **Only the validator promotes output.** A worker can propose an attempt manifest but cannot make
   it canonical.
7. **Every input is accounted for exactly once.** Duplicate, missing, and unexpected `custom_id`
   values are detected explicitly.
8. **Job completion is derived from the output ledger.** It is never inferred solely from a worker
   or shard status.
9. **A quote is immutable once accepted.** Later forecasts may alter execution but not the customer
   contract.
10. **A deadline is an absolute timestamp.** Durations are converted at submission and never
    reinterpreted by workers.
11. **Routing uses measured certified profiles.** Marketing specifications or provider GPU names
    are insufficient.
12. **Provider state is reconciled.** Create/stop calls may time out, repeat, or return ambiguous
    results without corrupting Firmbatch state.
13. **Customer data never enters provider control-plane metadata.** Provider APIs see opaque Firmbatch
    identifiers only.
14. **Tenant identity scopes every authoritative row and object.** Cross-tenant access must fail
    closed.
15. **Retries must not change the customer-visible sampling contract.** Seeds and sampling parameters
    remain pinned for the request, while permitted numerical variation is governed by the quality
    profile.
16. **Billing is based on reconciled valid work.** A launched GPU, a worker success flag, or an
    uploaded object is not by itself billable customer output.
17. **Forecasts are versioned evidence.** Every admission and hedge decision records the forecast,
    model version, input facts, and decision reason that existed at that moment.
18. **No deployment claim is “proven” until observed.** Tests establish implemented behaviour;
    staged failure drills and pilot runs establish operational evidence.

## 6. Target system shape

### 6.1 AWS control plane

- Public API behind a managed load balancer or API gateway.
- API, scheduler/controller, validator/accounting, and provider reconciler as independently runnable
  process roles. They may share a codebase and deployment initially.
- ECS Fargate for long-running control-plane services unless another choice is justified in an ADR.
- RDS PostgreSQL Multi-AZ as authoritative metadata and ledger storage.
- S3 for immutable input, attempt output, canonical output, certification, and benchmark artifacts.
- SQS plus a transactional outbox for asynchronous commands/events; SQS delivery is never ownership.
- ECR for immutable control-plane and worker images referenced by digest.
- KMS, Secrets Manager, CloudWatch and OpenTelemetry-compatible traces/metrics.
- Terraform roots for bootstrap/shared resources, test, and production.

### 6.2 GPU execution plane

- Provider adapters reconcile desired capacity with external provider state.
- GPU workers start from pinned images or deterministic bootstrap definitions.
- Workers make outbound connections only; no inbound administrative port is required.
- Workers claim shards, download immutable inputs directly from S3, execute the pinned runtime,
  upload attempt outputs directly to S3, and return only metadata/manifests to the control plane.
- Workers have short-lived, least-privilege credentials and cannot promote canonical output or alter
  a customer contract.

### 6.3 Core records

At minimum, model the following separately:

- Tenant
- API credential
- Input file and immutable input manifest
- Batch job
- Quote and accepted contract
- Request record / output-ledger entry
- Shard
- Shard attempt
- Lease generation and heartbeat
- Worker and worker session
- Provider capacity request and provider instance
- Model artifact
- Runtime image
- Execution profile and certification result
- Benchmark observation
- Forecast snapshot
- Scheduling/hedging decision
- Usage and price ledger entry
- Audit event

## 7. How to use this roadmap with GPT-5.6 and Claude

For each milestone:

1. Give GPT-5.6 this document, the current repository tree, `docs/STATE.md`, and the
   chosen milestone.
2. Ask it to inspect the repository before proposing work.
3. Ask it to divide the milestone into the smallest ordered implementation prompts that each end in
   a reviewable, tested repository state.
4. Give Claude one implementation prompt at a time.
5. After each implementation prompt, run the required checks and ask for an adversarial review
   against the milestone invariants.
6. Update `docs/STATE.md` with `CURRENT`, `PLANNED`, and `VERIFIED LIVE` distinctions.
7. Mark the milestone complete only when its completion gate is satisfied with saved evidence.

Suggested prompt contract:

```text
Implement Firmbatch roadmap milestone <N>, subtask <name>.

First inspect the repository, its instructions, `docs/STATE.md`, ADRs, and tests. State the
current behaviour and the exact gap. Propose a bounded plan before editing.

Preserve every Firmbatch invariant in the roadmap. Do not implement work assigned to a later
milestone unless it is the smallest prerequisite; if so, identify it explicitly. Add or update
tests for normal behaviour, duplicated delivery, stale ownership, partial failure, and tenant
isolation where relevant.

Finish by running the repository's full validation suite and reporting:
- files changed;
- decisions made;
- tests and results;
- remaining risks;
- whether this subtask's acceptance criteria are met;
- what remains before milestone <N> is complete.
```

### 7.1 Where the differentiating work lands

| Product capability | Primary milestones | Supporting milestones |
| --- | --- | --- |
| Deliberate v0 → v1 migration | 1 | 2–10 |
| Heterogeneous GPU certification | 12–13 | 8, 19–20 |
| Deadline forecasting | 16 | 11–12, 15, 17–18 |
| Interruption recovery | 15 | 9, 14, 18, 20 |
| Token-aware scheduling | 11 | 7, 12, 16–18 |
| Supply hedging | 18 | 14, 16–17, 21 |
| Reliable output accounting | 10 | 6–9, 15, 19–20 |
| Proving the price/deadline trade-off | 21 | 12, 16–18, 20 |

---

# Numbered build milestones

## R0 — Repository operating foundation (prerequisite)

**Status:** [ ] Not started · [x] In progress · [ ] Complete · [ ] Blocked

R0 is not a product milestone and adds no product behaviour. It is the prerequisite that
makes every numbered milestone below executable by an agent without the result having to be
taken on trust. Milestone 1 cannot honestly report a completion gate until R0 is in place,
because "complete only when its gate passes with saved evidence" presupposes a repository
that defines what evidence is and can tell you mechanically whether the gates passed.

### Objective

Make the roadmap's §7 working contract enforceable rather than aspirational: one canonical
set of instructions both agents read, one verification command all three callers run, one
state document, one policy engine, and an evidence standard with a stated provenance format.

### Build

- **Instructions.** `AGENTS.md` canonical for every agent; `CLAUDE.md` imports it and adds
  only Claude-specific surfaces. A rule has one home.
- **Verification.** `scripts/verify-repository.sh` as the single entry point, invoked
  identically by the human, the `verify` skill, and CI. Gates: repository layout, agent
  configuration parses and is read-only where it claims to be, no credential file or
  database is tracked, property tests, `ruff check`, agent policy tests.
- **State.** `docs/STATE.md` as the one state document, distinguishing CURRENT, PLANNED,
  VERIFIED LIVE, HISTORICAL, and NOT VERIFIED. `docs/tasks/current.md` for active work.
  `docs/adr/` for decisions.
- **Evidence.** A stated provenance header, an immutability rule, and the `record-evidence`
  skill that applies both.
- **Policy.** One deterministic pre-tool guard shared by both agents, covering the
  irreversible classes: evidence, destructive git, destructive filesystem, credentials,
  cloud mutation, billable launch.
- **Review.** Three read-only reviewers defined for both agents.
- **CI.** A workflow that reproduces the parent-directory package import and calls the same
  verification script.

### Non-negotiable properties

1. **The guard is a guardrail, not a boundary.** It exists to stop an aligned agent reaching
   an irreversible action by accident. Nothing in this repository may describe it as a
   sandbox or a security control, and it must not lock its own configuration — an agent that
   cannot edit the guard cannot fix it. Human approval for those files is an instruction.
2. **One home per rule.** No duplicated skill body, no gate spelled out in both CI and a
   skill, no second state document.
3. **A claim is VERIFIED only with a captured artifact.** Passing right now is not evidence.
   Evidence captured before the code it describes was committed is not evidence of it.
4. **R0 changes no product behaviour.** v0 defects found while doing R0 are recorded in the
   defect register in `docs/STATE.md` and left unfixed; they are Milestone 1 inputs.

### Required artifacts

- `docs/adr/0001-agentic-repository-operating-model.md` recording the decisions and their
  limits.
- A v0 defect register in `docs/STATE.md`, each entry located in the code.
- `docs/evidence/r0/` containing the verification gates and the policy-engine run, captured
  **at or after** the commit that introduces the R0 files.

### Completion gate

R0 is complete only when:

- `scripts/verify-repository.sh` passes every gate, and the human, the `verify` skill, and CI
  all invoke that same script;
- no document in the repository overstates the guard, or labels as VERIFIED anything without
  a captured artifact behind it;
- `docs/STATE.md` is the only state document, and the roadmap references it by name;
- the three read-only reviewers are read-only in configuration, not only in prose;
- the R0 evidence artifacts exist and cite a commit that actually contains the R0 files; and
- CI has been executed by a runner at least once. Until then CI is NOT VERIFIED.

---

## Milestone 1 — Characterize v0 and define the v0 → v1 migration boundary

**Status:** [ ] Not started · [ ] In progress · [ ] Complete · [ ] Blocked

### Objective

Use the existing v0 as an executable prototype to learn cheaply, establish an honest baseline, and
decide explicitly which parts will be retained, hardened, replaced, or deleted. This milestone is
the bridge into v1; it is not an attempt to turn v0 itself into the customer pilot.

The v0 test should answer two different questions without confusing them:

1. **Mechanism question:** do the current controller, worker, lease, partial-result, and provider
   paths behave as expected under controlled failure?
2. **Migration question:** which observed behavior and code are trustworthy enough to carry into the
   v1 architecture?

A successful v0 run is diagnostic evidence. It is not yet evidence of safe request-level accounting,
heterogeneous quality, calibrated deadlines, or a production customer data path.

### Migration principles

- Preserve working concepts and measured facts, not accidental interfaces.
- Do not harden a v0 payload path that v1 deliberately replaces.
- Reproduce every important v0 discovery as a v1 invariant or regression test.
- Record failures and ambiguous outcomes; do not reduce the baseline to one successful demo run.
- Distinguish “the final count looked right” from “every request has one correctly fenced canonical
  result.”
- Keep v0 spend bounded. Larger customer-scale evidence belongs to the later v1 qualification
  milestones.

### Required v0 inventory

Inspect the actual repository and create a versioned migration matrix. Do not assume this table is
complete until it has been reconciled against the code.

| v0 component or behavior | Initial migration decision | Destination in v1 |
| --- | --- | --- |
| Local subprocess provider and chaos harness | Retain and extend | Milestones 9, 15, and 20 |
| Provider API probe | Retain as supply-qualification tooling | Milestones 12 and 14 |
| Deadline-controller loop | Retain the control-loop concept; replace uncalibrated heuristics | Milestones 16 and 18 |
| Lease-based shard claim | Replace with owner + attempt ID + monotonic generation fencing | Milestone 9 |
| Worker heartbeats and dead-worker reaping | Retain behavior; rewrite against fenced attempts | Milestones 9 and 15 |
| Partial result chunks | Retain the economic goal; replace mutable/direct result handling | Milestones 9–10 |
| Result upsert keyed by job/request | Replace last-write-wins behavior with immutable attempts and validator promotion | Milestone 10 |
| Direct payload/result traffic through the control plane or database | Replace | Milestone 6 |
| Job/shard completion derived from worker status or aggregate counts | Replace with output-ledger reconciliation | Milestone 10 |
| Fixed record-count shards | Replace with token-aware planning | Milestone 11 |
| “Accepted output” and cost-per-output accounting | Replace with valid-response plus input/output-token accounting | Milestones 10 and 17 |
| Verda-specific create/delete logic | Wrap in a reconciled semantic provider adapter | Milestone 14 |
| v0 database records | Treat as disposable unless an explicit migration requirement is discovered | Milestones 3 and 6–10 |

For each row, record:

- current source files and tests;
- current behavior and authority;
- known defects and unverified assumptions;
- retain/harden/replace/delete decision;
- target milestone and target interface;
- whether a temporary compatibility layer is required; and
- the evidence that will allow the v0 implementation to be removed.

### Known correctness hypotheses to test first

Convert the known v0 concerns into executable adversarial tests before interpreting chaos output:

1. A worker with an expired lease attempts to heartbeat and finish after another worker has reclaimed
   the shard.
2. Two attempts produce different responses for the same `(job_id, request_id)`.
3. A worker dies after uploading a result chunk but before finishing its shard.
4. A worker reports shard completion while one or more required requests are missing.
5. Structurally invalid results exist in storage when job completion is evaluated.
6. The controller dies after work is produced but before it is reconciled.
7. Duplicate result delivery arrives before, during, and after retry settlement.
8. A provider create call succeeds remotely but times out locally and is retried.
9. A provider delete call returns ambiguously while the instance remains billable.

These tests are expected to reveal gaps. A failing test is valuable baseline evidence; it does not
have to be repaired inside v0 when a later milestone replaces the relevant path. Every unresolved
failure must, however, be linked to the v1 milestone and acceptance test that closes it.

### V0 experiment A — local destructive baseline

Run the existing local-provider batch with several workers and hard-kill workers during different
execution phases.

Capture at minimum:

- release/commit identity and configuration;
- input request count and unique IDs;
- stored result count and accepted/valid count as v0 currently defines them;
- missing, duplicate, conflicting, and unexpected request IDs;
- shard claims, lease expiries, reclaims, and late settlements;
- recomputed work after each kill;
- controller/worker timestamps and deadline result; and
- the difference between what the status API reports and what an independent reconciliation script
  derives from raw state.

**Gate:** The run is reproducible, and the report explains why the observed final count does or does
not establish correctness. Every discovered defect has a regression test or an explicit target v1
milestone.

### V0 experiment B — provider control-plane qualification

Probe the first supplier with no customer workload and with a strict spend/capacity cap.

Measure and save:

- real instance-type and location identifiers;
- quoted and realized price plus billing granularity;
- spot/interruptible and firm/on-demand semantics;
- availability-query accuracy;
- create-to-visible, create-to-SSH, and create-to-worker-ready distributions;
- create and delete idempotency behavior;
- delayed listing and ambiguous timeout behavior;
- actual GPU SKU, memory, driver, and CUDA observations;
- preemption notice behavior, including the absence of notice;
- persistent disk/volume behavior and orphan cleanup; and
- the provider API/SDK version used for every observation.

Treat supplier documentation and earlier generated notes as hypotheses until the probe observes
them.

**Gate:** A dated supply-profile artifact exists with raw observations, uncertainties, spend, and
operator cleanup confirmation. No unexplained instance, disk, IP, or other billable resource
remains.

### V0 experiment C — minimal real GPU vertical slice

Run one deliberately small real generative shard on one GPU, one model, and one runtime. Use
synthetic/non-sensitive data. The purpose is to validate bootstrap and integration, not to create a
customer-facing benchmark.

Measure:

- capacity acquisition and worker bootstrap;
- model download/load and cache behavior;
- exact GPU/runtime/model identities;
- time and token throughput;
- result transport and persistence behavior;
- shutdown and final provider charges; and
- one forced worker deletion if the correctness limitations are clearly called out in the report.

The workload may include classification for easy inspection, but it must also contain at least one
ordinary generative request shape so the path is not accidentally specialized to labels.

**Gate:** A real GPU completes at least one shard, the instance is removed, costs are reconciled,
and every observed integration issue is assigned to a v1 milestone. The result must not be described
as customer-pilot proof.

### Required artifacts

- `docs/STATE.md` separating CURRENT, PLANNED, and VERIFIED LIVE behavior.
- A v0 architecture and data-flow snapshot.
- The completed retain/harden/replace/delete migration matrix.
- Reproducible local chaos commands and an independent reconciliation report.
- Provider qualification report with dated raw observations.
- Minimal real-GPU run report with exact runtime identities and cost.
- A v0 defect/risk register linked to later milestone acceptance gates.
- An ADR defining the cutover strategy and when v0 code may be deleted.

### Completion gate

Milestone 1 is complete only when:

- the existing v0 has been run and characterized rather than trusted from documentation;
- known stale-lease, last-write-wins, premature-completion, and invalid-output risks are represented
  by executable tests or reproducible failing cases;
- every v0 component has an explicit retain/harden/replace/delete decision;
- the first provider's operational and billing behavior has been observed with bounded spend;
- one minimal real-GPU inference path has been exercised and cleaned up;
- no v0 result is being presented as pilot-ready customer proof; and
- every material v0 gap is linked to the numbered v1 milestone that closes it.

## Milestone 2 — Freeze the pilot contract and evidence model

**Status:** [ ] Not started · [ ] In progress · [ ] Complete · [ ] Blocked

### Objective

Turn the product promise into machine-representable contract fields and measurable pilot outcomes
before implementation choices silently define them.

### Build

- Write the initial API and contract specification.
- Define supported request parameters and explicit validation limits.
- Define `service_class`, `quality_profile`, valid-response target, deadline semantics, quote expiry,
  price cap/fixed price, and credit policy.
- Define pilot comparison baselines: hyperscaler batch API, direct GPU rental, and at least one
  specialist inference provider where relevant.
- Define what evidence is machine-observed versus estimated versus supplied by a provider.
- Version `docs/STATE.md` and establish the ADR format.
- Obtain representative customer batch samples or construct a versioned surrogate corpus until
  real samples are available.

### Required tests and evidence

- Contract examples for accepted, rejected, expired, cancelled, partially invalid, and missed-deadline
  jobs.
- JSON schemas or typed schemas that reject ambiguous deadlines and unbounded output tokens.
- A written definition of every pilot success metric and how it will be measured.

### Completion gate

- No core commercial term exists only in prose or UI state.
- The same contract can be interpreted unambiguously by the API, scheduler, accounting service, and
  customer.
- A real or surrogate evaluation corpus is versioned and reproducible.

## Milestone 3 — Establish the architecture, domain model, and state machines

**Status:** [ ] Not started · [ ] In progress · [ ] Complete · [ ] Blocked

### Objective

Create the authoritative domain model before adding provider behavior.

### Build

- Record the control-plane/data-plane split and authority rules in ADRs.
- Implement job, shard, attempt, capacity-request, and worker-session state machines as pure domain
  logic.
- Keep the accepted commercial contract separate from mutable execution state.
- Define legal transitions and terminal states.
- Define reason codes for validation failure, admission rejection, interruption, capacity failure,
  runtime failure, output invalidity, deadline breach, cancellation, and exhaustion.
- Define idempotency keys for every mutating customer and worker operation.

### Required tests and evidence

- Exhaustive transition-table tests.
- Property tests or generated tests proving illegal transitions remain illegal.
- Tests proving accepted quote fields cannot be mutated by execution code.
- Tests proving completion cannot occur from shard status alone.

### Completion gate

- Every transition is enforced in the domain/store boundary, not only in callers.
- Terminal and retryable outcomes are distinguishable without parsing human-readable error text.

## Milestone 4 — Create the production delivery foundation

**Status:** [ ] Not started · [ ] In progress · [ ] Complete · [ ] Blocked

### Objective

Make every later milestone deployable and observable without repeatedly rebuilding delivery
machinery.

### Build

- Establish the repository/package structure and dependency boundaries.
- Add formatting, linting, type checking, unit tests, integration tests, security scans, dependency
  audits, and documentation checks to CI.
- Build immutable multi-architecture images and publish them by digest.
- Create Terraform bootstrap, test, and production roots with remote state and locking.
- Deploy an empty but authenticated control plane to test and production.
- Promote the same built artifacts from test to production with an approval gate.
- Add rollback by retained immutable release identity.
- Add database migrations with forward and rollback/repair procedures.

### Required tests and evidence

- A clean checkout passes the entire validation suite.
- A release is built once, deployed to test, verified, and promoted unchanged.
- A prior release can be selected and restored.
- Pull requests cannot apply production infrastructure.
- Third-party CI actions and base images are pinned to immutable identities.

### Completion gate

- A no-op service is live in isolated test and production environments.
- Deployment, rollback, secrets, logs, alarms, and infrastructure drift have documented operator
  procedures.

## Milestone 5 — Implement tenant identity and isolation

**Status:** [ ] Not started · [ ] In progress · [ ] Complete · [ ] Blocked

### Objective

Make multi-tenancy structural rather than a later filter added to single-tenant tables.

### Build

- Implement tenant-scoped API credentials with hashing, rotation, expiry, and revocation.
- Put `tenant_id` in every tenant-owned primary/foreign key relationship.
- Enforce tenant scoping in repository/store interfaces and, where practical, PostgreSQL row-level
  security.
- Scope S3 keys, presigned operations, quotas, logs, metrics, and audit events by tenant.
- Define operator versus tenant authority without creating a large RBAC system.
- Add per-tenant request, token, storage, and concurrent-job quotas.

### Required tests and evidence

- Cross-tenant reads, updates, deletes, presigned URLs, idempotency keys, and guessed identifiers
  fail closed.
- Revoked credentials stop working without invalidating unrelated tenant credentials.
- Background workers cannot accidentally execute an unscoped tenant query.
- Audit records identify actor, tenant, operation, object, time, and outcome without payload leakage.

### Completion gate

- An adversarial tenant-isolation suite passes for every exposed resource type.
- No tenant-owned repository method accepts an unscoped identifier alone.

## Milestone 6 — Build the immutable S3 payload plane

**Status:** [ ] Not started · [ ] In progress · [ ] Complete · [ ] Blocked

### Objective

Move large inputs and outputs directly between customers/workers and object storage while the control
plane handles metadata only.

### Build

- Implement multipart presigned input upload and bounded presigned download.
- Create immutable input manifests containing object version, checksum, byte size, content type,
  record count, and tenant/job association.
- Validate uploaded objects before a job may proceed.
- Define attempt-specific output prefixes and immutable manifest formats.
- Add lifecycle, retention, deletion, and legal/audit behavior appropriate for the pilot.
- Encrypt storage and prevent public access.

### Required tests and evidence

- Large uploads never transit the API process.
- Modified, truncated, substituted, cross-tenant, and checksum-mismatched objects are rejected.
- Repeating finalize-upload is idempotent.
- Expired URLs and deleted jobs cannot be used to regain access.

### Completion gate

- A large synthetic batch can be uploaded, validated, and downloaded through the data plane with
  control-plane traffic proportional to manifests rather than payload bytes.

## Milestone 7 — Implement the customer batch API and ingestion pipeline

**Status:** [ ] Not started · [ ] In progress · [ ] Complete · [ ] Blocked

### Objective

Accept realistic general generative jobs and convert them into a canonical internal request set.

### Build

- Implement OpenAI-compatible file and batch resources where compatibility is useful.
- Add Firmbatch quote, deadline, service-class, and quality-profile extensions under an explicit
  namespace or versioned endpoint.
- Parse JSONL incrementally; never load an entire batch into API memory.
- Validate unique `custom_id`, model, endpoint, sampling parameters, token limits, supported context
  length, and tenant quotas.
- Tokenize inputs with the exact registered tokenizer and persist canonical input-token counts.
- Produce an immutable normalized request manifest.
- Return machine-readable per-line validation errors without admitting invalid work.

### Required tests and evidence

- Compatibility fixtures for accepted request shapes.
- Fuzz and boundary tests for malformed JSONL, duplicate IDs, enormous lines, invalid Unicode,
  unsupported parameters, zip bombs if archives are accepted, and excessive token counts.
- Ingestion is restartable and idempotent.

### Completion gate

- A representative customer JSONL file becomes a canonical, token-counted request manifest without
  executing inference or moving its body through the control plane.

## Milestone 8 — Deliver one reference inference path

**Status:** [ ] Not started · [ ] In progress · [ ] Complete · [ ] Blocked

### Objective

Complete the first genuine vertical slice on one model, one runtime image, one GPU type, and one
provider before introducing heterogeneous routing.

### Build

- Pin one model artifact and tokenizer by cryptographic identity.
- Build a GPU worker image containing the exact runtime and dependencies.
- Launch the runtime with fixed, reviewed arguments.
- Claim a small shard, download its input, execute inference, and upload an attempt manifest.
- Capture token usage, finish reason, runtime duration, GPU identity, software identities, and
  checksums.
- Shut down cleanly after work and on cancellation.

### Required tests and evidence

- Local or emulated worker protocol tests using a fake runtime.
- A live GPU smoke test with a real model.
- Repeating the same seeded corpus characterizes, but does not assume, determinism.
- Worker receives least-privilege, short-lived access and cannot alter contracts or canonical output.

### Completion gate

- One uploaded batch completes end to end on a real GPU and produces fully attributable attempt
  output.
- All runtime/model/software identities can be reconstructed from saved provenance.

## Milestone 9 — Implement leases, attempts, fencing, and canonical promotion

**Status:** [ ] Not started · [ ] In progress · [ ] Complete · [ ] Blocked

### Objective

Make distributed shard execution correct under duplicate delivery, slow workers, replacement, and
late writes.

### Build

- Add conditional shard claims with owner, attempt ID, lease generation, expiry, and heartbeat.
- Increment generation on every successful reclaim.
- Fence heartbeat, progress, manifest submission, validation, and settlement by generation.
- Store worker output only under immutable attempt prefixes.
- Have the validator verify checksums and promote exactly one attempt in a database transaction.
- Make late or stale workers harmless.
- Add bounded retry policy and terminal exhaustion reasons.

### Required tests and evidence

- Duplicate queue delivery launches at most one authoritative attempt.
- A worker that wakes after lease loss cannot heartbeat or settle.
- A stale but otherwise valid output cannot replace the winning attempt.
- Validator crash before/after promotion is recoverable and idempotent.
- A shard cannot become complete with an empty or partial manifest unless the contract explicitly
  permits it.

### Completion gate

- A deterministic concurrency test repeatedly forces lease expiry and stale completion without
  producing double ownership or ambiguous canonical output.

## Milestone 10 — Build reliable per-request output accounting

**Status:** [ ] Not started · [ ] In progress · [ ] Complete · [ ] Blocked

### Objective

Make customer completion and billing derive from reconciled request-level facts.

### Build

- Create one authoritative ledger entry for every input `custom_id`.
- Validate output schema, identity, model/profile provenance, finish reason, checksum, and usage.
- Detect missing, duplicate, unexpected, corrupt, and conflicting responses.
- Select a single winning response when a retry produces multiple valid attempts.
- Record explicit terminal errors for unfulfilled requests.
- Assemble canonical result and error manifests without last-write-wins overwrites.
- Derive shard and job completion from ledger reconciliation.
- Produce usage ledger entries only from promoted valid responses.

### Required tests and evidence

- Every input is accounted for exactly once across arbitrary retry and duplication orderings.
- Job completion fails when output count, IDs, checksums, or ledger totals disagree.
- Reconciliation is idempotent after process and database retries.
- Accounting totals equal independently recomputed totals from canonical manifests.

### Completion gate

- No worker status or aggregate count can cause a false successful job.
- A customer can trace every input ID to a valid response or explicit terminal error and its billing
  treatment.

## Milestone 11 — Implement token-aware planning and sharding

**Status:** [ ] Not started · [ ] In progress · [ ] Complete · [ ] Blocked

### Objective

Plan work in units that predict GPU execution cost better than files, bytes, or request counts.

### Build

- Use exact input-token counts from the registered tokenizer.
- Estimate output-token distributions using maximum output tokens plus observed workload/model data.
- Bucket requests by prompt length and relevant generation parameters to reduce padding and runtime
  variance.
- Create shards with bounded predicted token work, memory envelope, and execution duration.
- Retain request ordering only where the API contract requires it; otherwise optimize packing.
- Support resharding only through a new plan/version, never by mutating an active shard invisibly.
- Record planner version and inputs for reproducibility.

### Required tests and evidence

- No request is dropped or duplicated during planning.
- Shard limits hold for adversarial length distributions.
- Planning the same immutable input with the same planner version is reproducible.
- Compared with naive record-count sharding, token-aware shards reduce duration variance on a
  representative corpus.

### Completion gate

- The planner demonstrably improves utilization or predictability on measured workloads.
- Every shard carries enough predicted-work metadata for forecasting and admission.

## Milestone 12 — Build the benchmark and telemetry system

**Status:** [ ] Not started · [ ] In progress · [ ] Complete · [ ] Blocked

### Objective

Collect the measurements required for certification, forecasting, pricing, and hedging.

### Build

- Create a versioned benchmark corpus spanning prompt lengths, output lengths, concurrency levels,
  sampling modes, and structured-output requests.
- Measure cold start, model load, time to first token where relevant, prefill throughput, decode
  throughput, total tokens/second, memory, OOM boundary, retry rate, and teardown time.
- Separate benchmark, synthetic, canary, and customer observations.
- Record provider, region, host, GPU UUID/SKU, runtime identity, model identity, and timestamps.
- Build an append-only observation schema and reproducible benchmark runner.
- Detect obviously contaminated runs and retain them with a reason rather than silently deleting
  inconvenient data.

### Required tests and evidence

- Metrics survive worker loss and duplicated reporting.
- Units and aggregation semantics are tested.
- A benchmark result can be reproduced from its corpus and profile identities.
- Telemetry contains no customer prompt or generated content by default.

### Completion gate

- At least the reference profile has measured throughput and startup distributions over the
  operating envelope needed by the planner.

## Milestone 13 — Implement heterogeneous GPU certification

**Status:** [ ] Not started · [ ] In progress · [ ] Complete · [ ] Blocked

### Objective

Make heterogeneous routing safe by certifying complete execution profiles rather than trusting GPU
labels.

### Build

- Create the execution-profile registry and immutable certification records.
- Define certification policies for structural correctness, numerical health, statistical quality,
  context limits, OOM envelope, throughput, and stability.
- Run the versioned reference corpus on each candidate profile.
- Compare candidate and reference distributions using declared task-specific and distributional
  metrics.
- Define `certified`, `quarantined`, `expired`, and `experimental` states.
- Automatically expire or require recertification after changes to any profile component.
- Route admitted work only to profiles certified for its model and quality profile.
- Add continuous canaries and automatic quarantine for material regressions.

### Required tests and evidence

- Changing model hash, tokenizer, runtime digest, engine arguments, precision, GPU SKU, driver, or
  CUDA stack creates a distinct profile requiring certification.
- A deliberately corrupted or degraded profile fails certification.
- A quarantined/expired profile cannot receive admitted work, even if capacity is available.
- Certification decisions retain input evidence, policy version, results, and approver/automation
  identity.

### Completion gate

- At least two materially different GPU SKUs pass the same customer-facing quality profile for one
  supported model.
- The system can explain why each routed profile is allowed.

## Milestone 14 — Implement provider adapters and desired-state reconciliation

**Status:** [ ] Not started · [ ] In progress · [ ] Complete · [ ] Blocked

### Objective

Control multiple GPU suppliers without allowing ambiguous provider API behavior to corrupt internal
state.

### Build

- Define a provider adapter around semantic operations: quote/discover, request capacity, inspect,
  terminate, and classify provider state.
- Give every capacity request a stable Firmbatch idempotency identifier.
- Reconcile desired internal capacity against observed provider state.
- Handle create timeouts, repeated calls, delayed visibility, unknown instances, partial failures,
  and termination races.
- Bootstrap workers with only opaque Firmbatch identifiers and short-lived credentials.
- Normalize price, currency, billing granularity, region, GPU identity, preemption signals, and firm
  versus interruptible semantics.
- Record raw provider evidence safely without letting provider text drive state transitions.

### Required tests and evidence

- Provider fakes simulate timeouts after successful creation, duplicate instances, delayed listing,
  price changes, failed termination, and malformed responses.
- Reconciliation converges without creating an unbounded number of instances.
- Orphan detection never kills a resource until ownership and grace-period rules are satisfied.

### Completion gate

- Two interruptible supply pools and one firm/on-demand path can be controlled through the same
  semantic contract.
- Repeated reconciliation converges after injected ambiguous outcomes.

## Milestone 15 — Prove interruption recovery

**Status:** [ ] Not started · [ ] In progress · [ ] Complete · [ ] Blocked

### Objective

Turn worker/provider loss into an ordinary, bounded execution event rather than an exceptional
operator repair.

### Build

- Detect explicit preemption notices, missed heartbeats, provider disappearance, worker crash, and
  runtime failure.
- Expire/reclaim leases and reschedule remaining work.
- Preserve already promoted per-request outputs where the shard/result format permits safe partial
  progress; otherwise retry the immutable shard.
- Ensure replacement attempts keep the sampling contract and provenance.
- Add retry budgets, failure-domain diversification, poison-request isolation, and terminal
  exhaustion.
- Create automated chaos scenarios that kill workers at controlled execution phases.

### Required tests and evidence

- Kill before download, during model load, during generation, during upload, after manifest upload,
  during validation, and after promotion.
- Remove an entire provider pool while a job is active.
- Duplicate late results never corrupt the output ledger.
- Recovery does not leak capacity, lose requests, double-bill, or silently reset the deadline.

### Completion gate

- A large batch completes correctly during repeated forced interruptions without manual database or
  object-store repair.
- Recovery time and recomputed work are measured and available to the forecast model.

## Milestone 16 — Build calibrated deadline forecasting

**Status:** [ ] Not started · [ ] In progress · [ ] Complete · [ ] Blocked

### Objective

Estimate the probability distribution of completion time using measured behavior rather than a
single optimistic throughput number.

### Build

- Model remaining token work per shard and job.
- Incorporate startup/model-load distributions, profile throughput curves, concurrency, queueing,
  provider acquisition time, interruption rate, retry cost, output-length uncertainty, validation,
  and finalization.
- Produce p50/p90/p95/p99 completion timestamps and probability of meeting the contract deadline.
- Version forecast code, parameters, and data windows.
- Save immutable forecast snapshots at quote, admission, schedule, material progress, interruption,
  hedge, and completion.
- Compare predicted distributions with actual outcomes and report calibration error.
- Start with an explainable simulation/Monte Carlo model; introduce more complex learning only when
  measured error justifies it.

### Required tests and evidence

- Synthetic scenarios with analytically obvious outcomes.
- Forecast worsens when work grows, capacity disappears, startup slows, or interruption risk rises.
- Forecast improves when certified capacity is added.
- Historical replay tests do not use future information.
- Predictions and actual completion times are recorded with consistent clocks and units.

### Completion gate

- On held-out benchmark/replay jobs, interval coverage and deadline-probability calibration meet a
  declared pilot threshold.
- Every forecast can be explained from its saved inputs and model version.

## Milestone 17 — Implement quote, admission, and the capacity book

**Status:** [ ] Not started · [ ] In progress · [ ] Complete · [ ] Blocked

### Objective

Accept only contracts that the measured supply and margin model can credibly underwrite.

### Build

- Estimate input work exactly and output work probabilistically under declared maximums.
- Maintain a capacity book by time window, model/profile compatibility, supply pool, and confidence.
- Prevent double-selling the same firm capacity.
- Calculate expected cost, stressed cost, hedge reserve, provider billing granularity, platform
  margin, and customer quote.
- Generate an immutable quote with expiry and assumptions.
- Admit only when deadline probability and margin exceed service-class thresholds under the accepted
  capacity plan.
- Reject or counteroffer impossible jobs with a later deadline, smaller scope, alternate profile, or
  higher price.

### Required tests and evidence

- Concurrent admission cannot reserve the same capacity twice.
- Price changes after quote acceptance do not change the customer contract.
- Impossible deadlines fail before customer commitment.
- Stress cases include maximum output, slower throughput, failed spot acquisition, and fallback use.
- Quote and realized-cost reconciliation is exact to the defined accounting precision.

### Completion gate

- A customer can receive, accept, and execute a quote backed by an explicit capacity reservation and
  forecast snapshot.
- The system can explain both accepted and rejected admissions.

## Milestone 18 — Implement supply hedging and deadline-risk escalation

**Status:** [ ] Not started · [ ] In progress · [ ] Complete · [ ] Blocked

### Objective

Use cheap supply first while preserving the committed deadline through measured, auditable
escalation decisions.

### Build

- Define a capacity ladder across cheap interruptible pools and firm fallback.
- Continuously recompute deadline probability from remaining work and observed capacity.
- Add policy thresholds for acquiring another pool, upgrading hardware, duplicating only critical
  tail work, and activating firm capacity.
- Account for acquisition delay, minimum billing increments, cancellation cost, and correlated
  failure domains.
- Track every hedge as a decision record with alternatives, expected deadline effect, and expected
  cost.
- Cancel speculative duplicate work safely once an authoritative result wins.
- Bound hedge spend by the accepted contract and configured risk reserve.

### Required tests and evidence

- Cheap capacity completing normally does not trigger unnecessary firm spend.
- Slower throughput, preemption, or acquisition failure raises risk and triggers the correct rung.
- A hedge that arrives late cannot overwrite completed output or double-bill the customer.
- Firm fallback is physically exercisable, not merely a provider API status.
- Policy replay over historical jobs shows the price/deadline trade-off versus cheap-only and
  firm-only baselines.

### Completion gate

- During a forced loss or slowdown of the primary cheap pool, Firmbatch escalates automatically and
  meets the test deadline using the fallback path.
- The saved decision trail explains the extra cost and risk reduction.

## Milestone 19 — Complete observability, operations, and security hardening

**Status:** [ ] Not started · [ ] In progress · [ ] Complete · [ ] Blocked

### Objective

Make the system operable during a real pilot without reading databases manually or exposing customer
data.

### Build

- Structured logs, metrics, traces, correlation IDs, and dashboards for API, ingestion, scheduling,
  provider reconciliation, workers, validation, forecasting, hedging, accounting, and delivery.
- Alerts for stalled jobs, lease churn, invalid output, deadline risk, provider divergence, forecast
  miscalibration, DLQs, orphan capacity, unusual spend, quota exhaustion, and failed delivery.
- Operator views for jobs, shards, attempts, workers, capacity, forecasts, hedges, certification,
  usage, and audit events.
- Semantic operator actions: pause admission, cancel job, quarantine profile, disable provider pool,
  force reconciliation, and activate approved fallback. Avoid arbitrary state editing.
- Backup, restore, retention, tenant deletion, incident response, credential rotation, key rotation,
  and disaster-recovery procedures.
- Network boundaries, least-privilege IAM, dependency/container scanning, signed or attested images,
  secret handling, rate limits, and abuse limits.

### Required tests and evidence

- Restore authoritative state and manifests into an isolated environment.
- Alerts are exercised, delivered, and acknowledged.
- Logs/traces/metrics are scanned for customer payload and secret leakage.
- Operator actions are authorized, idempotent, audited, and cannot bypass state-machine invariants.
- Security review covers tenant isolation, presigned URLs, worker compromise, provider API compromise,
  supply-chain integrity, and denial-of-wallet.

### Completion gate

- An operator can diagnose and safely respond to every rehearsed pilot failure using documented
  interfaces and runbooks.
- Backups and alarms have been proven by use, not merely configured.

## Milestone 20 — Run full-system qualification and destructive testing

**Status:** [ ] Not started · [ ] In progress · [ ] Complete · [ ] Blocked

### Objective

Demonstrate that independently correct components remain correct under concurrency, scale, and
failure.

### Build

- Create a repeatable end-to-end qualification harness.
- Exercise multiple tenants, jobs, providers, GPU profiles, model choices, and overlapping deadlines.
- Run load, soak, concurrency, chaos, upgrade, rollback, quota, and cost-guardrail scenarios.
- Verify compatibility through the public customer API rather than internal shortcuts.
- Compare Postgres, S3 manifests, output ledger, provider inventory, and customer-visible state after
  every destructive scenario.
- Track every qualification observation with environment, release identity, method, and date.

### Required scenarios

- API/control-plane restart during every major operation.
- Database failover and worker reconnect.
- Duplicate and delayed queue messages.
- Worker replacement and stale completion.
- Complete cheap-provider outage.
- Object upload truncation or checksum mismatch.
- Validator crash around promotion.
- Forecast model rollout and rollback.
- Runtime/profile quarantine with active jobs.
- Tenant cancellation and deletion during execution.
- Budget limit and runaway-capacity prevention.

### Completion gate

- Qualification produces no missing or duplicated customer requests, ambiguous ownership, ledger
  mismatch, cross-tenant access, uncontrolled capacity, or unrecoverable job state.
- Known limitations are written explicitly and accepted for the pilot.

## Milestone 21 — Prove the pilot price/deadline trade-off

**Status:** [ ] Not started · [ ] In progress · [ ] Complete · [ ] Blocked

### Objective

Produce evidence that Firmbatch is economically useful, not only technically impressive.

### Build

- Run representative real or replayed customer workloads through the complete public path.
- Run enough repeated trials to observe supply and interruption variance.
- Compare three policies on equivalent work:
  1. cheapest available capacity with no hedge;
  2. firm/on-demand capacity only; and
  3. Firmbatch’s forecast-driven hedging policy.
- Measure quote accuracy, realized cost, valid-response rate, deadline success, fallback usage,
  interruption loss, customer price, gross margin, and operational intervention.
- Document where Firmbatch wins, loses, or cannot safely quote.
- Complete at least one real customer delivery under an accepted quote and deadline.

### Pilot-ready technical evidence

The exact scale may be adjusted to the customer workload, but the evidence must include:

- at least two certified GPU SKUs for a supported model;
- two interruptible pools and one exercised firm fallback;
- repeated forced interruption and full-pool-loss trials;
- a substantial batch large enough that scheduling and hedging materially affect cost and finish
  time, not a smoke-test-sized job;
- complete per-request reconciliation and accounting;
- forecast-versus-actual calibration results;
- a comparison against cheap-only and firm-only counterfactuals; and
- a dated production observation of the complete customer path.

### Completion gate

Firmbatch is pilot-ready only when the evidence supports all of these statements:

1. The service accepts and delivers a real general generative batch through its public contract.
2. It routes across heterogeneous certified GPUs without losing the declared quality profile.
3. It recovers automatically from interruption without missing, duplicating, or double-billing
   requests.
4. Its deadline forecasts are calibrated well enough to drive admission and escalation.
5. Its supply hedge materially improves deadline reliability relative to cheap-only execution.
6. Its realized price remains meaningfully below firm-only execution for the target workload, or
   offers another measured advantage the customer values.
7. The operator can explain every material scheduling, cost, certification, and accounting decision.
8. A customer is willing to run another batch, pay, sign a pilot, or provide an equally strong
   demand signal after seeing the result.

If the first seven pass but the eighth does not, the engineering pilot succeeded and the business
hypothesis did not yet succeed. Do not conceal that distinction by adding more infrastructure.

---

## 8. Cross-milestone definition of done

A milestone is complete only when:

- its code and schema changes are merged;
- unit, integration, adversarial, and relevant live tests pass;
- infrastructure and operational changes are deployable from a clean environment;
- observability exists for the new behavior;
- security and tenant-isolation implications were reviewed;
- documentation distinguishes implemented behavior from live-proven behavior;
- migrations and rollback/repair behavior are documented;
- no TODO in the critical path is being counted as completion; and
- the milestone’s saved evidence is linked from `docs/STATE.md`.

## 9. Decision rules while building

Use these rules to prevent ambition from turning into unrelated complexity:

1. Prefer sophistication that improves certification, prediction, recovery, utilization, hedging,
   accounting, or economic evidence.
2. Prefer one deeply measured runtime over several shallow adapters.
3. Prefer immutable evidence and reconciliation over optimistic status flags.
4. Prefer explicit state machines over implied sequences of API calls.
5. Prefer measured distributions over nominal performance claims.
6. Prefer a manual semantic operator action over a premature general policy engine, except where
   automatic deadline protection is the product itself.
7. Add a provider, GPU, model, or runtime only when it expands a real feasible/price frontier or is
   required by a pilot.
8. Do not call a feature production-ready because it has CI, Terraform, or dashboards. Production
   readiness for Firmbatch is demonstrated by correct behavior during GPU and provider failure.
9. Keep demand and supply discovery running alongside implementation. New evidence may change model,
   provider, deadline, and quality priorities without changing the core correctness invariants.
10. When a milestone reveals that the price/deadline hypothesis is false, preserve the evidence and
    reconsider the product rather than hiding the result behind a more sophisticated architecture.
