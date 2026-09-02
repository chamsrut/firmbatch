# Firmbatch v0 to v1 implementation roadmap

**Status:** Canonical implementation sequence
**Product repository:** `chamsrut/firmbatch`
**Marketing repository:** `chamsrut/firmbatch-site`
**Target architecture:** `docs/architecture/v1-target-architecture.md`
**Last consolidated:** 2 September 2026

This roadmap sequences the work required to move the current Firmbatch v0 prototype toward the approved v1 target. It includes the customer account, portal, and billing work needed to make the target execution architecture usable as a product.

Authority is deliberately separated:

- `docs/STATE.md` says what the code does now.
- `docs/architecture/v1-target-architecture.md` says what v1 must become.
- This file says in what order to build and prove it.
- `docs/architecture/v1-capability-baseline.md` is the initial gap map; Milestone 1 replaces it with a code-cited audit.

There is no timeline encoded here. A milestone is complete only when its entire gate passes with repository evidence.

## Product surfaces

### Public marketing site

- Repository: `chamsrut/firmbatch-site`
- Domain: `firmbatch.com`
- Purpose: explanation, trust, documentation, and conversion.
- Primary actions point to signup and login at `app.firmbatch.com`.
- It contains no authenticated product or billing management.

### Customer product application

- Product repository: `chamsrut/firmbatch`
- Suggested location: `apps/customer-web`
- Domain: `app.firmbatch.com`
- Purpose: identity, workspaces, billing, acceptance policies, jobs, quotes, monitoring, results, and invoices.
- It uses the native Firmbatch API and never accesses PostgreSQL, S3, providers, or workers directly.

### Product API

- Domain: `api.firmbatch.com`
- Used by the customer application, Python SDK, CLI, and customer automation.
- Customer payload bytes move directly between the customer and S3 through presigned URLs.

### Internal and supplier surfaces

Customer accounts never grant access to provider credentials, capacity offers, raw supplier information, operator settlement, internal routing controls, certification administration, provider reconciliation, or execution infrastructure. Those capabilities require separate identities, permissions, and interfaces.

## Implementation-language boundary

- Python remains the control-plane language: one image, three roles.
- The operator capacity agent is a static Rust or Go binary. Select exactly one in a focused design ADR before its implementation.
- The execution worker is a signed, digest-pinned OCI image. Python plus vLLM is acceptable.
- Firmbatch-authored C++ is not required for v1. Upstream CUDA/C++ dependencies inside the inference image do not change that boundary.
- TypeScript is the default recommendation for the customer web application.

## Milestone 0 — establish the canonical product plan

### Deliverables

- Convert the complete target PDF into `docs/architecture/v1-target-architecture.md`.
- Add this consolidated roadmap.
- Add `docs/architecture/v1-capability-baseline.md`.
- Mark `docs/firmbatch-pilot-roadmap.md` superseded while preserving it as historical context.
- Record authority, product surfaces, and language boundaries in an ADR.
- Align `README.md`, `docs/STATE.md`, and `docs/tasks/current.md` with the merged R0 foundation and the new target.
- Make no product-behavior change.

### Completion gate

The repository has one unambiguous, version-controlled source of truth matching the target PDF; the old roadmap cannot be mistaken for an active plan; repository verification passes; and the diff contains documentation only.

## Milestone 1 — audit v0 against the target

Audit code and tests across:

- Tenancy and authorization.
- Job lifecycle and idempotency.
- Quotes and accepted contracts.
- Acceptance policies.
- Spend envelopes.
- S3 payload storage.
- Shards, attempts, leases, and fencing.
- Provider execution and reconciliation.
- Validation and canonicalization.
- Provider execution, delivery-valid, and accepted-unit accounting.
- Operator settlement.
- Customer identity and billing.
- Deployment, secrets, and observability.

For every current component choose **retain**, **harden**, **replace**, or **delete**, with code citations, destination, tests, and migration order.

Expected starting decisions:

- Retain and extend the local provider, chaos harness, and provider probe as qualification tooling.
- Retain the deadline-control-loop concept, but replace its heuristic and authority.
- Replace unfenced shard leases with attempts and monotonic lease generations.
- Preserve incremental partial-result behavior as an economic goal, but write immutable attempt-scoped S3 output.
- Replace SQLite, mutable result upserts, the shared-token API, and runtime worker bootstrap.

### Completion gate

A reviewed migration matrix accounts for every product module and identifies the proof required for its destination.

## Milestone 2 — shared product foundation

Build the backend foundation required by both accounts and jobs:

- PostgreSQL migrations.
- Tenant and workspace records.
- Transactional outbox.
- Audit events.
- Tenant-scoped authorization.
- Secrets and encryption model.
- Test and production configuration boundaries.
- Idempotent API mutation framework.
- Explicit lifecycle state machines.

Every tenant-owned authoritative row and S3 key is tenant-scoped.

### Completion gate

Cross-tenant reads and writes fail closed in automated tests, and duplicate mutations produce one contractual effect.

## Milestone 3 — customer accounts and portal shell

### Identity

- Signup and login.
- Email verification.
- Credential recovery.
- Session management, logout, and revocation.

### Workspaces

- Create and rename workspaces.
- Memberships, roles, and permissions.
- Invite and remove members.
- Select active workspace.

### API credentials

- Create scoped credentials.
- Display a credential only once.
- Revoke and rotate.
- Record last use and audit events.
- Keep browser sessions distinct from API credentials.

### Customer application

- Authenticated layout and onboarding.
- Account, workspace, team, and permission settings.
- API credential management.
- Empty job and billing sections ready for later milestones.

### Completion gate

A new customer can register, verify identity, create a workspace, invite a member, and create a scoped API credential without gaining access to supplier or internal operations.

## Milestone 4 — commercial and billing foundations

### Firmbatch-authoritative records

PostgreSQL remains authoritative for quotes, quote versions and expiry, accepted contracts, pricing terms, usage, delivery-valid work, accepted units, credits, adjustments, and Firmbatch invoices. An accepted quote is immutable.

### Payment-provider projection

The payment provider is authoritative for payment-method status, payment attempts, collection outcome, and provider-side identifiers. Implement:

- Billing identity and address.
- Payment-method setup.
- Signed webhook verification.
- Idempotent, immutable webhook event ingestion.
- Reconciliation and backfill.
- Internal payment-state projection.

Browser redirects and success pages are never authoritative payment evidence.

### Customer billing interface

- Billing profile and payment method.
- Quotes and accepted terms.
- Current usage and accepted-unit records.
- Invoices, credits, and payment status.

Billing belongs only in `app.firmbatch.com`.

### Completion gate

Duplicate and out-of-order webhooks cannot double-charge, regress payment state, or alter an accepted quote.

## Milestone 5 — customer job contract and payload path

Implement the customer workflow:

1. Define a declarative acceptance policy.
2. Create a job.
3. Upload input through a presigned S3 URL.
4. Submit an immutable provider-independent JobSpec.
5. Receive and accept a quote.
6. Poll or receive a webhook for status.
7. Download canonical results through a presigned URL.
8. Cancel where contractually permitted.

Required properties:

- No provider field in JobSpec.
- Absolute deadlines.
- Idempotency keys on mutations.
- Immutable accepted quotes, inputs, and manifests.
- Attempt-scoped output prefixes.
- No customer payload bytes in the API process or PostgreSQL.

### Completion gate

A tenant can submit a job and retrieve its contract without payload bytes entering the metadata plane.

## Milestone 6 — target execution and accounting

Before implementation, decide Rust versus Go for the operator capacity agent in a focused ADR. Then build:

- PostgreSQL-backed shards and immutable attempts.
- Monotonic lease generations and stale-worker fencing.
- Immutable attempt manifests.
- Validator and canonicalizer roles.
- Exactly one canonical result per request.
- Three separate accounting ledgers.
- Per-job and per-tenant spend envelopes.
- Transactional outbox and SQS wake-ups.
- Provider reconciliation.
- Execution-centric provider interface.
- Verda and Lyceum adapters.
- Short-lived worker credentials.
- Signed, digest-pinned execution image.
- Closed evidence-based cancellation causes.
- Window offers and supply classes.
- Settlement Structures A and B.
- Static operator capacity agent in the selected language.

### Completion gate

Forced duplicate delivery, stale workers, worker loss, and ambiguous provider operations cannot corrupt canonical results, retroactively change commercial terms, or exceed admitted spend.

## Milestone 7 — complete customer journey

```text
Visit firmbatch.com
-> sign up at app.firmbatch.com
-> verify account
-> create workspace
-> configure billing
-> define acceptance policy
-> upload input
-> submit job
-> review and accept quote
-> monitor execution
-> download canonical results
-> inspect accepted-unit accounting
-> receive invoice
-> observe payment status
```

Use polling initially unless measured product behavior justifies a more complex realtime channel.

### Completion gate

A new customer completes the journey without internal operator intervention except for an explicitly retained commercial or operational decision.

## Milestone 8 — deploy, secure, and prove flex

Deploy:

- `firmbatch.com`, `app.firmbatch.com`, and `api.firmbatch.com`.
- ALB and TLS.
- Three ECS roles.
- RDS PostgreSQL.
- S3 payload plane.
- SQS and transactional outbox.
- Secrets Manager and KMS.
- CloudWatch and OpenTelemetry.
- Isolated test and production environments.
- Explicit database-migration delivery step.

Prove:

- Account and workspace isolation.
- Payment-webhook idempotency.
- Quote immutability.
- Spend-envelope enforcement.
- Worker interruption and cross-provider recovery.
- Canonical-result correctness.
- Complete accepted-unit reconciliation.
- Full customer journey in production.

### Release boundary

Enable the 72-hour flex tier first. Keep the 24-hour firm tier built but dark until the same workload survives measured provider loss and cross-provider recovery.

## Explicitly deferred

Do not put these on the v1 critical path:

- OpenAI Batch translation adapter.
- Embeddings, training, and multimodal inference.
- Customer-supplied validator containers.
- Calibrated forecasting and statistical quality certification.
- Fragment harvesting and yield pricing.
- Marketplace functionality.
- Polished enterprise billing or highly granular enterprise RBAC.

## Product-level integration acceptance path

```text
Create account
-> create workspace
-> configure billing
-> define acceptance policy
-> submit job
-> accept quote
-> monitor execution
-> download results
-> receive invoice
```

This is the integration test connecting identity, commercial terms, execution, accepted-unit accounting, and collection.
