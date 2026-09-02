# Firmbatch v1 capability baseline

**Status:** Milestone 0 baseline, not the full Milestone 1 audit
**Compared:** current `main` at `2f03da55fa3a4fd991f9eaad7cacf33d842a4459` against `docs/architecture/v1-target-architecture.md`
**Assessed:** 2 September 2026

This is the starting map for the detailed code audit. It prevents a prototype feature with a similar name from being mistaken for the target implementation. Milestone 1 must cite code and tests for every final retain, harden, replace, or delete decision.

Status meanings:

- **Implemented:** matches the target at this assessment depth.
- **Partial:** useful target behavior exists but required behavior is incomplete.
- **Missing:** no target implementation found.
- **Inconsistent:** an existing implementation conflicts with a target invariant and must be replaced or substantially redesigned.
- **Built but dark:** target implementation exists behind a release gate.
- **Deferred:** explicitly outside v1.

## Customer and commercial product

| Capability | Baseline | Evidence and next question |
| --- | --- | --- |
| Customer signup, verification, login, recovery, and sessions | Missing | No customer identity model or authenticated portal exists. |
| Workspaces, memberships, roles, and permissions | Missing | Current API has no tenant or workspace boundary. |
| Scoped customer API credentials | Missing | The shared `FB_TOKEN` is not a tenant-scoped credential system. |
| Customer web application | Missing | No `app.firmbatch.com` surface exists in the product repository. |
| Billing identity and payment method | Missing | No billing domain or payment-provider projection exists. |
| Quotes and immutable accepted terms | Missing | Current commands accept parameters directly; no quoted commercial contract is persisted. |
| Accepted-unit usage and customer invoices | Missing | Current cost reporting is not customer billing. |
| Payment webhooks and reconciliation | Missing | No payment-provider integration exists. |
| Separation of customer and supplier/internal permissions | Missing | There are no distinct identity or authorization domains. |

## Customer job contract and payload plane

| Capability | Baseline | Evidence and next question |
| --- | --- | --- |
| Native Firmbatch Job API | Partial | FastAPI exposes prototype job and worker operations, but not the target tenant-scoped contract. |
| Canonical provider-independent JobSpec | Inconsistent | v0 operator commands and provider selection expose execution choices absent from the customer contract. |
| Absolute deadline and explicit lifecycle | Partial | A deadline loop and job states exist, but the target state machine and contractual transitions do not. |
| Mutation idempotency | Missing | No persisted idempotency-key framework protects all mutations. |
| Versioned acceptance policies frozen at admission | Missing | Prototype validation is not a declarative, versioned customer policy. |
| Presigned input and result access | Missing | Prototype payload and result paths are not the target S3 design. |
| Immutable S3 inputs, manifests, and attempt prefixes | Missing | No S3 payload plane exists. |
| Python SDK and CLI | Partial | The CLI is useful operator/prototype tooling; a customer SDK and target API client are not present. |

## State, messaging, and execution control

| Capability | Baseline | Evidence and next question |
| --- | --- | --- |
| PostgreSQL as single metadata authority | Inconsistent | v0 uses SQLite and must migrate rather than be treated as the target store. |
| Transactional outbox | Missing | No atomic state-and-event outbox exists. |
| SQS as non-authoritative wake-up | Missing | No target messaging layer exists. |
| Token-estimated shards | Missing | Prototype sharding is request/row oriented. |
| Immutable attempt identity | Missing | v0 has shards and retries but no first-class immutable attempt record. |
| Monotonic lease generation and stale-worker fencing | Inconsistent | Leases exist, but a stale worker is not fenced from newer work. |
| Short-lived, scoped worker credentials | Missing | Shared-token worker authentication violates the target trust boundary. |
| Hard per-job and per-tenant spend envelopes | Inconsistent | `max_workers` limits concurrency, not cumulative launches or admitted spend. |
| Provider reconciliation after ambiguous operations | Missing | Direct provider calls are not an authoritative reconciliation loop. |
| W_min and job-specific expected-value routing | Missing | The existing deadline controller is a prototype heuristic, not target admission/routing. |

## Providers and workers

| Capability | Baseline | Evidence and next question |
| --- | --- | --- |
| Execution-centric provider interface | Inconsistent | Existing adapters are worker/instance oriented and need a target execution contract. |
| Local provider and chaos harness | Partial | Valuable qualification tooling exists and should be retained and extended. |
| Verda VM execution | Partial | Adapter and provider probe exist; nomination, reconciliation, security, and target ledger integration do not. |
| Lyceum serverless execution | Missing | No adapter found. |
| Operator capacity agent | Missing | No Rust or Go agent exists. Language choice remains Rust versus Go. |
| Signed, digest-pinned execution image | Missing | Current worker bootstrap installs and fetches code at runtime. |
| vLLM-backed execution worker | Partial | Python worker can invoke vLLM, but it does not implement target attempts, credentials, manifests, or fencing. |
| Firmbatch-authored C++ runtime | Deferred | Not required by the target. Upstream vLLM/CUDA native code may remain inside the execution image. |
| Certified GPU/runtime profiles | Missing | No global certification registry or enforced target profile exists. |

## Validation, canonicalization, and accounting

| Capability | Baseline | Evidence and next question |
| --- | --- | --- |
| Isolated validator role | Missing | Structural validation is not a separately trusted service role. |
| Canonicalizer with one result per request | Partial/Inconsistent | Result upsert supplies a useful deduplication property, but mutable overwrite is not immutable attempt canonicalization. |
| Provider-execution ledger | Partial/Inconsistent | Prototype worker billing is too coarse and uses known rounding behavior that needs replacement. |
| Delivery-valid ledger | Missing | No separately attributed delivery-valid record exists. |
| Customer-accepted-unit/revenue ledger | Missing | No customer acceptance and NCR record exists. |
| Structures A and B settlement | Missing | No operator-period settlement engine exists. |
| Closed evidence-based cancellation enum | Missing | Target causes, actor, payable state, and accepted-window effect are not implemented. |
| Window offers and supply classes | Missing | No two-sided nomination state machine exists. |

## Deployment and release boundary

| Capability | Baseline | Evidence and next question |
| --- | --- | --- |
| ALB/TLS and three ECS service roles | Missing | v0 is a local/single-control-plane prototype. |
| RDS, S3, SQS, Secrets Manager, and KMS | Missing | Target AWS data and security planes are not deployed. |
| Terraform with isolated test and production | Missing | No target environment definition found. |
| Metadata-only observability and leakage tests | Missing | Logging does not yet meet the target automated boundary. |
| 72-hour flex tier | Missing as a product tier | Some prototype deadline execution exists; it is not the target commercial tier. |
| 24-hour firm tier | Missing; target state is built but dark | Schema, hedge, credit policy, and release gate still need implementation and proof. |

## Explicitly deferred from v1

The following are not gaps for the v1 completion gate: OpenAI Batch translation adapter, fragment harvesting, yield pricing, calibrated forecasting, statistical quality certification, customer-supplied validator containers, training, embeddings, and multimodal inference.

## Milestone 1 audit priorities

1. Map every current state mutation and persistence table to retain, harden, replace, or delete.
2. Prove the exact useful properties of local execution, chaos recovery, partial result handling, and the provider probe.
3. Identify every trust-boundary violation created by the shared token, mutable results, and unfenced leases.
4. Separate observed provider behavior from comments and unverified assumptions.
5. Turn this baseline into a code-cited migration matrix with named tests and completion evidence.
