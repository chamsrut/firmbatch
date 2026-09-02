# Firmbatch v0 to v1 migration audit

**Status:** Milestone 1 audit, pending repository review
**Audited commit:** `547877382fd5eb080b20192eb68b750f5f8b2cca`
**Target:** `docs/architecture/v1-target-architecture.md`
**Roadmap:** `docs/firmbatch-v1-roadmap.md`
**Audited:** 2 September 2026

## 1. Conclusion

Firmbatch v0 is a useful executable prototype, not a production foundation that can be hardened in place.

The code proves or usefully models five concepts:

1. Work is leased rather than permanently assigned.
2. A dead worker's work can return to a shared pool.
3. Partial chunks can reduce recomputation after interruption.
4. A controller can use observed throughput and remaining time as feedback.
5. A local provider, deterministic engine, and chaos path can make execution behavior cheap to exercise.

Every one of those concepts must be re-expressed behind the target contracts. The current persistence model, API, worker protocol, result authority, provider lifecycle, accounting, and security model conflict with one or more target invariants.

The migration decision is therefore:

- **Retain measured concepts and diagnostic assets.**
- **Harden only the local qualification tooling that remains useful during migration.**
- **Replace all customer, state, execution-authority, provider-lifecycle, and accounting interfaces.**
- **Delete v0 code after the replacement proof listed in ADR 0003 exists.**

No v0 database or API compatibility layer is required: there is no production customer contract or authoritative customer data to migrate.

### Product-surface boundary

`app.firmbatch.com` is exclusively the customer application. It contains customer identity,
workspaces, billing, jobs, results, and invoices. The operator capacity agent does not appear in,
install from, or run as part of that application.

The operator capacity agent is separately distributed software installed and run inside an
operator's own infrastructure. It uses an outbound, operator-scoped control-plane protocol and
has its own credentials and lifecycle. Customer identities cannot configure it, view its raw
capacity or settlement data, or access operator/internal controls. If an operator administration
interface is added later, it must be a separate product surface with separate identities and
permissions—not a section of the customer application.

## 2. Audit method and evidence boundary

The audit reconciled the complete product tree at the audited commit:

```text
control/app.py
control/db.py
controller.py
providers/base.py
providers/local.py
providers/verda.py
worker/agent.py
fb.py
demo/make_requests.py
tests/test_recovery.py
requirements.txt
environment.yml
pyproject.toml
```

It also read the target architecture, canonical roadmap, current state, active tasks, ADRs, repository instructions, and historical v0 evidence.

Code is the source for CURRENT behavior. Existing captured artifacts remain HISTORICAL unless the repository's evidence rules say otherwise. This audit is code inspection and migration analysis; it does not claim real-provider behavior, real-GPU behavior, customer accounting correctness, deadline calibration, or pilot readiness.

## 3. Current architecture and data flow

```text
operator CLI (fb.py)
  |
  +--> create job, inline request payloads, deadline, acceptance spec
  |       |
  |       v
  |   FastAPI control plane (control/app.py)
  |       |
  |       v
  |   SQLite authority (control/db.py)
  |     jobs / shards / requests / results / workers / events
  |
  +--> deadline controller (controller.py)
          |
          +--> local subprocess provider
          |        `--> Python worker agent
          |
          `--> Verda create/delete API
                   `--> startup script downloads Python worker agent

worker agent
  --> shared bearer token
  --> claim shard with inline request payloads
  --> execute echo or vLLM
  --> apply customer acceptance logic itself
  --> post mutable result chunks to control plane
  --> declare shard done
```

There is no separate customer application, customer identity domain, payload plane, validator, canonicalizer, transactional outbox, provider reconciler, or payment system.

## 4. Current authorities

| Question | v0 authority | Target conflict |
| --- | --- | --- |
| Job contract | Mutable `jobs` row created directly as `running` (`control/db.py:26-36,116-139`) | No draft/upload/validation/quote/admission contract; no accepted immutable quote. |
| Work ownership | `shards.lease_worker` and expiry (`control/db.py:38-47,181-230`) | No immutable attempt ID or monotonic fencing generation. |
| Input payload | JSON stored in `requests.payload` and returned by claim (`control/db.py:50-56,133-135,201-213`) | Payload passes through SQLite and API rather than immutable S3 manifests. |
| Result authority | Last writer to `(job_id, request_id)` in `results` (`control/db.py:59-68,236-254`) | Mutable overwrite; worker output is directly customer-visible; no validator promotion. |
| Acceptance | Worker-side `make_acceptor` and self-reported `accepted` (`worker/agent.py:108-128,175-184`) | An untrusted worker decides the billed-unit flag. |
| Completion | Worker-declared shard state plus result row count (`control/app.py:98-109`; `control/db.py:335-395`) | Completion is not derived from a fenced canonical output ledger. |
| Provider state | Direct create/delete calls and local `workers` row (`controller.py:41-97`; `providers/verda.py:137-162`) | No desired state, operation identity, observation, or reconciliation. |
| Cost | Worker lifetime rounded into one aggregate ledger (`control/db.py:398-426`) | No provider-execution, delivery-valid, or accepted-unit separation. |
| Authentication | One shared `FB_TOKEN` for operator and every worker (`control/app.py:13-21`) | No tenancy, scopes, short-lived credentials, or customer/internal separation. |

## 5. Test and evidence inventory

`tests/test_recovery.py` is a deterministic script with fourteen assertions across six scenarios:

| Scenario | What it establishes | What it does not establish |
| --- | --- | --- |
| Expired lease is reaped and shard is claimable | Basic lease expiry behavior | Fenced ownership or stale-worker safety |
| Marked-dead worker releases a shard immediately | Fast controller-initiated recovery | Real unannounced preemption or provider cleanup |
| Partial rows survive and only missing IDs are reissued | Lower recomputation in the mutable result model | Immutable attempt provenance or conflict detection |
| Duplicate rows do not increase the result count | Primary-key count idempotence | Same-payload idempotence; conflicting retry output is overwritten |
| Fully answered shard causes no further work | Result-count shortcut | Safe canonical completion or structural validity |
| Sub-increment worker life bills one increment | Minimum billing increment | Correct ceiling behavior at an exact increment; D2 remains untested |

There are no automated tests for:

- FastAPI authorization boundaries or endpoint behavior.
- Controller launch, scale, deadline, or cumulative-spend behavior.
- Worker retry failures and partial protocol failures.
- Verda create/delete ambiguity or reconciliation.
- Stale-worker publication and settlement.
- Unexpected request IDs, wrong shard IDs, output cardinality mismatch, or invalid output.
- Tenant isolation, quote immutability, S3 payload isolation, or billing webhooks.

The historical local artifacts support limited row-level and controller-initiated recovery claims. They do not establish an unannounced SIGKILL path, a deadline verdict, real provider behavior, real GPU behavior, or request-level accounting correctness.

## 6. Target-domain audit

| Target domain | v0 state | Code basis | Migration decision | Destination and required proof |
| --- | --- | --- | --- | --- |
| Tenancy and authorization | Missing/inconsistent | Shared token in `control/app.py:13-21`; no `tenant_id` columns in `control/db.py:26-92` | Replace | Milestone 2: tenant/workspace schema, scoped credentials, deny-by-default cross-tenant tests. Milestone 3: browser identity and memberships. |
| Customer/internal/supplier separation | Missing | Same API and bearer credential for operator and worker; provider values accepted from worker registration | Replace | Milestones 2, 3, and 6: customer-only app; separately distributed operator agent; distinct principals, scopes, service credentials, and privilege-matrix tests. |
| Job lifecycle | Inconsistent | Job is inserted directly as `running`; `set_job_status` permits arbitrary writes (`control/db.py:116-151`) | Replace | Milestones 2 and 5: explicit state machine; invalid-transition and concurrency tests. |
| Idempotent mutations | Missing | Every `create_job` makes a random new ID (`control/db.py:116-139`) | Replace | Milestone 2: persisted idempotency records; duplicate and conflicting-key tests. |
| Quotes and accepted contracts | Missing | No quote or contract tables; CLI parameters immediately create work | Replace | Milestones 4 and 5: versioned quote, expiry, immutable acceptance, replay tests. |
| Acceptance policies | Inconsistent | Arbitrary JSON stored on job; worker executes and reports acceptance (`control/db.py:35,116-139`; `worker/agent.py:108-128`) | Replace | Milestones 5 and 6: versioned policy frozen at admission; trusted validator applies it; audit and replay tests. |
| Payload storage | Inconsistent | Input and output bodies are stored in SQLite and cross API process (`control/db.py:50-68,133-135,236-266`) | Replace | Milestone 5: tenant-scoped immutable S3 prefixes, presigned access, automated payload-leakage tests. |
| Shards and planning | Partial/inconsistent | Fixed record-count chunks in `create_job` (`control/db.py:126-136`) | Replace | Milestone 6: token-estimated planning and target shard manifest tests. |
| Attempts, leases, and fencing | Partial/inconsistent | Leases and reaping exist; no attempt identity/generation and `finish_shard` is unfenced (`control/db.py:160-230`) | Retain concept; rewrite | Milestone 6: conditional claim, monotonic generation, stale heartbeat/publish/finish tests. |
| Partial-result economics | Partial/inconsistent | Chunk posting and missing-ID reissue (`worker/agent.py:175-188`; `control/db.py:201-213`) | Retain goal; replace storage | Milestone 6: immutable attempt manifests and request-level canonical promotion; kill-after-chunk tests. |
| Canonicalization | Inconsistent | Last-write-wins upsert (`control/db.py:236-254`) | Replace | Milestone 6: all attempts retained, one fenced canonical result per request, conflicting-output tests. |
| Validation | Missing/inconsistent | Worker performs only simple acceptance checks; no provenance or usage validation | Replace | Milestone 6: isolated validator role; schema, identity, digest, token-usage, and invalid-output tests. |
| Provider interface | Inconsistent | Worker-centric `prepare/launch/kill/capacity_available` (`providers/base.py:12-25`) | Replace | Milestone 6: execution-centric quote/capacity/launch/observe/cancel/usage/reconcile contract with operation IDs. |
| Verda integration | Partial/inconsistent | Create/delete and list calls exist; no reconciliation; runtime bootstrap injects shared token | Retain observations/probe; replace adapter | Milestone 6: reconciled Verda execution adapter, opaque provider metadata, ambiguity/orphan tests. |
| Lyceum integration | Missing | No module | Build | Milestone 6: serverless execution adapter and duplicate-invocation reconciliation tests. |
| Operator capacity agent | Missing | No Rust or Go artifact | Build | Milestone 6 after focused language ADR: separately released software running in the operator's infrastructure, with signed outbound envelopes and credential-scope tests; never part of the customer app. |
| Routing and admission | Inconsistent | Greedy rate projection and mutable spot-to-firm switch (`controller.py:28-83`) | Retain feedback-loop concept; replace implementation | Milestone 6: `W_min`, job-specific `E[V]`, certified profiles, persisted reasons, deterministic admission tests. |
| Spend envelopes | Inconsistent | `max_workers` limits concurrency only (`controller.py:66-83`) | Replace | Milestones 4 and 6: admitted per-job/per-tenant envelope, simultaneous and cumulative caps, repeated-launch fault tests. |
| Cancellation | Inconsistent | Mutable job status and worker stop reasons (`control/app.py:157-161`; `control/db.py:298-323`) | Replace | Milestone 6: closed cause/actor enum, evidence, payable state, and window consequences. |
| Provider-execution accounting | Partial/inconsistent | Worker rows and elapsed-time estimate (`control/db.py:71-83,398-426`) | Replace | Milestone 6: reconciled provider usage with immutable commercial snapshots. |
| Delivery-valid accounting | Missing | No separate record | Build | Milestone 6: attributed delivery-valid attempt ledger and validator tests. |
| Customer accepted-unit/revenue accounting | Inconsistent | Worker boolean plus aggregate count (`control/db.py:64,365-368`) | Replace | Milestones 4 and 6: accepted-unit ledger, NCR linkage, refunds/credit semantics. |
| Operator settlement | Missing | No period, share, floor, window, or statement model | Build | Milestone 6: Structures A/B, month-wide max, cancellation credit, late-collection true-up tests. |
| Customer identity, portal, and billing | Missing | No application or domain model | Build | Milestones 3, 4, and 7: complete authenticated customer journey. |
| Deployment and observability | Missing/inconsistent | Local Uvicorn/SQLite; provider instance bootstraps from public control plane | Replace | Milestone 8: ALB/ECS/RDS/S3/SQS/KMS/Secrets/OTel/Terraform; leakage and recovery drills. |
| 72-hour flex and dark firm tiers | Missing | Deadline parameter is not a commercial tier | Build | Milestone 8: flex release proof; firm remains flagged until provider-loss evidence exists. |

## 7. Component migration matrix

| v0 component | Current behavior and authority | Known defects/limits | Decision | Target destination | Compatibility layer | Removal evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Root/control/worker/provider `__init__.py` files | Package markers only | Current import requires running from repository parent | Replace as packaging is introduced | Milestone 2 packaging foundation | None | New package imports and verification pass without v0 root layout. |
| `control/db.py` schema and connection | SQLite/WAL contains every body, state, and ledger | No tenancy/FKs/outbox; busy-timeout drift; incompatible authority | Replace | Milestone 2 PostgreSQL metadata; Milestones 5-6 domain tables | No data migration; optional read-only diagnostic export only | Target migrations and isolation tests pass; no required v0 data remains. |
| `control/db.py` job functions | Creates immediately-running job and mutable status | No idempotency, lifecycle, quote, or transition guards | Replace | Milestones 2, 4, 5 | None | Native v1 create/upload/submit/quote/accept journey passes. |
| `control/db.py` claim/reap behavior | Leases pending shard and reaps expiry | D1; no attempt/generation; arbitrary worker may claim | Retain concept; rewrite | Milestone 6 attempts and fencing | Test adapter only | Stale-owner matrix passes for heartbeat, upload, validate, canonicalize, settle. |
| `control/db.py` request/result functions | Inline bodies and mutable upsert; missing IDs reissued | Unexpected IDs accepted; conflict history destroyed | Retain missing-work concept; replace implementation | Milestones 5-6 S3 manifests, attempts, canonical ledger | None | Duplicate/conflicting/partial attempt tests prove one canonical result and complete history. |
| `control/db.py` worker/event/ledger functions | Worker self-registration, mutable liveness, aggregate estimated cost | D2, D9; self-reported commercial fields; no three-ledger separation | Replace | Milestone 6 execution, observation, cancellation, and ledger records | None | Provider reconciliation and all settlement tests pass. |
| `control/app.py` worker API | Shared-token register/heartbeat/claim/results | D1, D3-D5; no worker/job binding or scoped credentials | Replace | Milestone 6 internal execution protocol | None | Short-lived credential, scope, fencing, replay, and stale-worker tests pass. |
| `control/app.py` operator job API | Inline payload create/status/output/ledger/cancel | No tenancy/idempotency/quote; payload crosses API | Replace | Milestones 2, 4, 5 native `/v1` API | No public compatibility promise | SDK/CLI/portal contract tests use only target API. |
| `GET /agent.py` | Serves worker source from public control plane | D5; unsigned mutable runtime code | Delete | Signed digest-pinned execution image in Milestone 6 | None | All executions boot a pinned image; endpoint absent. |
| `GET /health` | Unauthenticated liveness response | No readiness/dependency separation | Retain endpoint concept; replace implementation | Milestone 8 service health/readiness | ALB-compatible path may be retained | Deployment probes distinguish liveness/readiness without leaking metadata. |
| `controller.py` | Greedy observed-rate scaler, stale-worker detection, spot-to-firm switch | D7/D9; no kill-by, forecast evidence, certification, spend envelope, reconciliation | Retain control-loop concept; replace implementation | Milestone 6 controller/reconciler | None | Deterministic routing, spend, provider ambiguity, and deadline abandonment tests pass. |
| `providers/base.py` | Worker-centric prepare/launch/kill/capacity interface | Cannot express execution classes, observations, usage, operation identity, windows | Replace | Milestone 6 execution-centric provider contract | Temporary adapter only for local harness | Verda and Lyceum implement target conformance suite. |
| `providers/local.py` | Subprocess worker launch and hard kill | D6 PID-reuse risk; process map not shared with chaos CLI | Retain and harden | Milestone 6 qualification provider | Yes, solely as test infrastructure | Target attempt/fencing/partial-failure suites run through local provider. |
| `providers/verda.py` list/probe behavior | Lists instance types and asks availability | SDK conformance unverified; probe failure is treated as capacity; spot price not clearly reported | Retain as qualification seed; harden | Milestone 6 provider qualification and cost book | Read-only probe can survive temporarily | Dated provider observations and adapter conformance replace comments. |
| `providers/verda.py` lifecycle/bootstrap | Direct create/delete; startup script downloads code and embeds shared token | D3/D9; no operation record/reconcile; mutable unsigned worker | Replace | Milestone 6 reconciled execution adapter and pinned image | None | Ambiguous create/delete and orphan sweeps pass; no long-lived token in provider metadata. |
| `worker/agent.py` protocol | Shared-token self-register, heartbeat, claim, execute, post, finish | Ignores terminal post failure; unfenced; self-reports price and acceptance | Replace | Milestone 6 execution worker protocol | None | Credential, attempt, manifest, cardinality, and interruption tests pass. |
| `EchoEngine` | Deterministic, time-shaped local stand-in | Not inference evidence | Retain as test engine | Milestone 6 local qualification suite | Yes | Target local tests use it only with explicit synthetic labeling. |
| `VLLMEngine` | Minimal vLLM load/generate wrapper | No registered profile/digest/provenance/usage; one narrow request shape | Retain as spike/reference; rewrite production adapter | Milestone 6 signed execution image and certified runtime profile | None | Certified registered model runs with pinned runtime and complete usage/provenance. |
| Worker `make_acceptor` | Applies labels/JSON/nonempty rule on untrusted worker | Worker decides accepted/billed flag | Delete from worker; replace in trusted role | Milestones 5-6 policy service and validator | Policy fixture may be reused in tests | Versioned policy replay and accepted-unit ledger tests pass. |
| `fb.py` CLI shell | Serve/submit/run/watch/chaos/report/probe/demo | Monolithic operator API; D4/D6/D8; exposes provider selection and fake quote metric | Retain useful command journeys; replace internals | Python SDK/CLI across Milestones 5-7 | Thin transitional diagnostic commands only | Customer CLI uses native API; operator diagnostics are separated and scoped. |
| `fb.py` deadline parsing | Converts relative input to timestamp | Called twice on submission; accepts raw float; not contract-validated | Harden behind target schema | Milestone 5 JobSpec | CLI may keep relative UX | API persists one validated absolute UTC deadline; repeat parsing tests pass. |
| `fb.py` chaos path | Intends unannounced worker death | D6; kill is not durably recorded and historical run did not prove path | Retain and harden as diagnostic tooling | Milestone 6 fault harness; Milestone 8 drills | Yes | Reproducible kill phases produce expected fenced recovery evidence. |
| `fb.py` report/ledger UX | Prints fake/local cost per accepted output as quote input | D2/D9; collapses three ledgers; not quotable | Delete calculation; replace views | Milestones 4, 6, 7 | None | Customer usage/invoice and internal settlement reconcile independently. |
| `demo/make_requests.py` | Seeded synthetic classification JSONL | Classification-only shape; ordinary generative request absent | Retain and extend | Milestones 6-8 qualification fixtures | Yes | Fixture set includes ordinary generative shape and deterministic IDs without shared temp path. |
| `tests/test_recovery.py` | Fourteen v0 property assertions | Does not cover target ownership/accounting/security; billing boundary missed | Retain as legacy characterization; add target suites separately | Milestones 2 and 5-8 | Yes until cutover | All retained concepts have target regression tests; legacy script is no longer a release gate. |
| `requirements.txt` / `environment.yml` | Broad v0 runtime requirements and minimal conda env | No locked production/control/worker separation; worker installs at runtime | Retain only for frozen v0; replace | Milestones 2, 6, 8 packaging and images | Yes for v0 diagnostics | Reproducible role-specific builds and SBOM/digest records exist. |
| `pyproject.toml` v0 lint exceptions | Keeps full-tree R0 lint stable | Not packaging; frozen ignores intentionally preserve outgoing style | Retain until files are deleted; do not expand | Milestone 2 new-code configuration | Yes | V0 files and their per-file ignores are removed together. |
| README v0 instructions | Documents prototype and historical evidence | Line counts and provider claims drift; provider run is unsafe as product guidance | Retain with prototype warning; revise as replacement lands | Every milestone updates relevant guidance | Yes | Default README path describes supported target workflow only. |

## 8. Defect-to-milestone closure map

Existing defects remain unfixed; this table assigns their target closure.

| Defect | Target closure | Required proof |
| --- | --- | --- |
| D1 stale worker can finish a reclaimed shard | Milestone 6 | Old generation fails heartbeat, publish, validate, canonicalize, and settle after reclaim. |
| D2 billing adds an increment at exact boundary | Milestone 6, consumed by Milestone 4 | Provider usage reconciles exact billing increments; customer billing never derives from v0 worker lifetime. |
| D3 shared token embedded in provider startup script | Milestone 6 | One-time registration yields short-lived attempt/execution scope; provider metadata contains no long-lived secret. |
| D4 server prints live bearer token | Milestone 2 | Secret never appears in startup output or structured logs; leakage test fails on injection. |
| D5 public mutable worker-source endpoint | Milestones 6 and 8 | Endpoint removed; execution uses signed digest; health endpoint exposes no sensitive metadata. |
| D6 chaos may kill a recycled unrelated PID | Milestone 1 diagnostic hardening or Milestone 6 harness port | Harness owns an unambiguous process handle and proves target identity before kill. |
| D7 concurrency cap permits unlimited cumulative launches | Milestones 4 and 6 | Repeated create/timeout/churn cannot exceed job or tenant cumulative envelope. |
| D8 shared `/tmp/fb_demo.jsonl` path | Milestone 1 diagnostic hardening or fixture port | Concurrent runs use unique work directories and cannot overwrite one another. |
| D9 provider create/stop is recorded without reconciliation | Milestone 6 | Ambiguous create/delete, delayed list, duplicate operation, and orphan-sweep tests converge to provider truth. |

## 9. Additional code findings

These findings were not separately numbered in the pre-audit defect register.

| ID | Finding | Code | Consequence | Closure |
| --- | --- | --- | --- | --- |
| A1 | Any holder of the shared token may claim any running job using any `worker_id`; claim does not require a registered worker bound to that job. | `control/app.py:70-87`; `control/db.py:181-213` | Cross-job execution and fabricated ownership are possible. | Milestones 2 and 6 scoped principal plus conditional attempt claim. |
| A2 | `put_results` validates no request membership, shard membership, worker ownership, or result cardinality; SQLite has no foreign keys for these relations. | `control/db.py:22-93,236-254` | Unexpected IDs can enter the result count; results can be attributed to the wrong shard/job. | Milestone 6 manifest validation and fenced attempt ledger. |
| A3 | Worker `post()` returns `{}` after exhausting retries; chunk and finalization callers do not check acknowledgement. | `worker/agent.py:41-51,182-188` | A worker can discard a failed result upload and still attempt to finish the shard. | Milestone 6 durable manifest publication and acknowledged state transition. |
| A4 | `zip(batch, outs)` silently truncates if the engine returns fewer outputs, after which the worker declares the shard done. | `worker/agent.py:175-188` | A done shard may have missing required requests, producing a stuck job or incorrect completion shortcut. | Milestone 6 validator cardinality and output-ledger completion tests. |
| A5 | Acceptance is computed by the worker and stored without trusted re-evaluation. | `worker/agent.py:108-128,180`; `control/db.py:242-250` | A compromised or defective worker can invent customer-accepted/billable units. | Milestones 5-6 trusted policy version plus isolated validator. |
| A6 | Worker registration accepts provider, instance identity, type, and hourly price from the worker and the ledger consumes them. | `control/app.py:39-53`; `worker/agent.py:133-137`; `control/db.py:271-282,398-426` | Untrusted self-report influences provider attribution and cost. | Milestone 6 controller-owned execution record plus provider usage reconciliation. |
| A7 | A worker re-registering an existing ID updates only instance/type/price; it does not reset `state`, timestamps, or job. Claim does not check worker state. | `control/db.py:271-295`; `control/app.py:75-87` | A logically dead or wrong-job worker can still claim while remaining absent from live-worker control. | Milestone 6 immutable execution identity and scoped registration. |
| A8 | Controller continues after deadline unless status or remaining count ends the loop; no wall-clock kill-by exists. | `controller.py:37-67` | A stuck job can continue launching and billing after the contractual deadline. | Milestone 6 persisted kill-by and deadline-abandonment cause. |
| A9 | A capacity-query exception returns `True`. | `providers/verda.py:116-121` | Unknown provider state is treated as permission to launch billable capacity. | Milestone 6 conservative observation state and reconciled admission. |
| A10 | The controller switches future launches from spot to non-preemptible by mutating the provider object, without a quote version, hedge budget, or persisted decision. | `controller.py:68-83` | Execution can change to a more expensive supply class outside an admitted envelope. | Milestones 4 and 6 immutable quote plus capped hedge decision. |
| A11 | Relative deadline parsing is called once for persistence and again for display. | `fb.py:26-31,50-60` | The reported deadline is slightly later than the persisted deadline; the same input is interpreted twice. | Milestone 5 parse once into absolute JobSpec timestamp. |
| A12 | The provider probe prints `price_per_hour` while checking spot availability even though `spot_price_per_hour` is collected separately. | `providers/verda.py:123-133`; `fb.py:161-174` | Operator may read an on-demand price as the price corresponding to the spot availability result. | Harden provider qualification tooling before any cost conclusion. |
| A13 | The execution result contains no usage, artifact digest, tokenizer, runtime profile, GPU identity, or complete provenance. | `worker/agent.py:82-101,175-188`; `control/db.py:59-68` | Validity, certification, token accounting, and commercial attribution cannot be reconstructed. | Milestone 6 registered profiles, manifest schema, validator, and three ledgers. |

## 10. Target tests that must replace v0 trust

### Milestone 2

- Cross-tenant row, credential, idempotency record, and object-key access fails closed.
- Duplicate identical mutation returns one effect; a conflicting reuse is rejected.
- Lifecycle transitions are conditional and invalid transitions cannot race through.
- State change and outbox event are committed atomically.

### Milestone 5

- Payload bytes never enter API logs, request persistence, PostgreSQL, or queues.
- Accepted quote, policy version, JobSpec, and input manifest are immutable.
- Presigned access is tenant-scoped, expiry-limited, and object-prefix constrained.

### Milestone 6

- Stale generations fail every ownership-sensitive operation.
- Duplicate, conflicting, partial, missing, unexpected, and wrong-shard outputs remain attributable and cannot corrupt canonical state.
- Worker death after each publication phase converges to one canonical result per request.
- Ambiguous provider create/delete calls reconcile without orphaned spend.
- Simultaneous and cumulative spend envelopes survive controller retries and restarts.
- Provider execution, delivery-valid work, and accepted units reconcile independently.
- Structures A and B settle heterogeneous supply classes with frozen terms.

### Milestones 7 and 8

- The full customer journey completes without internal privilege leakage.
- Flex survives measured provider loss and cross-provider recovery before firm is enabled.
- Metadata-only observability is tested for payload and secret leakage.

## 11. Migration order

1. **Milestone 2:** establish new PostgreSQL, tenancy, authorization, state-machine, idempotency, audit, and outbox foundations alongside frozen v0.
2. **Milestones 3-4:** add customer identity and commercial records without coupling them to v0 execution authority.
3. **Milestone 5:** introduce the native JobSpec and S3 payload plane. No v0 payload path is reused.
4. **Milestone 6:** port the local provider, echo engine, fault concepts, and useful recovery behaviors into the new attempt/fencing/provider/validator architecture. Add Verda and Lyceum only through the target provider contract.
5. **Milestone 7:** connect the portal to the target API and complete the customer journey.
6. **Milestone 8:** deploy and prove flex. Remove v0 release paths only after ADR 0003's deletion conditions pass.

No temporary customer compatibility API is justified. Temporary code is limited to diagnostic adapters that let the local v0-shaped harness drive target interfaces during replacement.

## 12. Remaining risks and follow-ups

- Existing v0 defects remain present. Do not launch Verda through v0 or present v0 output as pilot proof.
- D1 still lacks a captured failing test; the target regression case is specified but not executed here.
- Historical chaos evidence still does not prove unannounced preemption.
- Provider behavior, real GPU integration, billing granularity, and cost remain unverified.
- `AGENTS.md` and `.agents/skills/milestone/SKILL.md` still directly name the superseded pilot roadmap. ADR 0002 and the pilot-roadmap banner establish the correct authority, but the protected configuration should be aligned in a separately approved change.
- README line counts and several provider claims remain stale; update them when the corresponding v0 surfaces are retired or re-qualified.

## 13. Milestone 1 gate assessment

The canonical Milestone 1 completion gate requires a reviewed migration matrix accounting for every product module and naming the destination and proof for each.

This document supplies that matrix, the architecture/data-flow snapshot, the authority map, target-domain gaps, defect closure map, required tests, and removal evidence. The gate is **ready for human review**. It becomes complete when this audit and ADR 0003 are reviewed, repository verification passes, and the documentation change is merged.

The superseded pilot roadmap listed billable provider qualification and a real-GPU run under its older Milestone 1. Those are not completion requirements in the canonical roadmap and were not run. They remain useful bounded qualification work only when a later target milestone explicitly authorizes the spend and evidence capture.
