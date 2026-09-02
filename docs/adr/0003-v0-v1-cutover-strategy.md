# ADR 0003: replace v0 beside the prototype, then retire it

- **Status:** Accepted
- **Date:** 2026-09-02
- **Decision owners:** Firmbatch product owner and maintainers
- **Related:** `docs/architecture/v0-to-v1-migration-audit.md`

## Context

Firmbatch v0 is an executable Python/SQLite prototype. It contains useful behaviors and diagnostic tooling, but its authoritative interfaces conflict with the v1 target: inline payloads, shared credentials, unfenced leases, mutable last-write-wins results, worker-decided acceptance, direct provider calls, and a collapsed cost ledger.

Attempting to incrementally harden those interfaces would spend effort on paths the target deliberately removes and would make it harder to tell which authority model is active.

There is no production customer data or public v0 API contract requiring migration compatibility.

## Decision

1. Build v1 alongside the frozen v0 prototype rather than evolving v0 tables and endpoints in place.
2. Treat v0 as diagnostic and historical:
   - no production customer traffic;
   - no new product features;
   - no claim of pilot readiness;
   - no real-provider launch through v0 unless separately and explicitly authorized for bounded qualification.
3. Port concepts, not interfaces:
   - local subprocess provider;
   - deterministic echo engine and seeded fixture;
   - fault injection and worker-loss phases;
   - leased-work behavior;
   - partial-result economic goal;
   - feedback-control concept;
   - read-only provider qualification observations.
4. Do not migrate the v0 SQLite database. Preserve historical evidence as immutable files; create new target records through target APIs and migrations.
5. Do not create a public v0 compatibility API. Temporary compatibility code is allowed only as test infrastructure that drives target interfaces and is deleted with the v0 harness.
6. Safety fixes to v0 are allowed only when required to run a bounded diagnostic without risking unrelated processes, credentials, or uncontrolled spend. Such a fix does not convert v0 into a product path.
7. Delete v0 executable paths only when all removal conditions below are met. Historical evidence and ADRs remain.
8. Keep the customer and operator products physically and logically separate:
   - `app.firmbatch.com` is customer-only;
   - the operator capacity agent is a separately distributed executable installed and run in the
     operator's infrastructure;
   - the agent uses separate operator-scoped credentials and an outbound control-plane protocol;
   - the agent, operator capacity, settlement records, and internal controls never appear in the
     customer application;
   - any future operator administration interface requires a separate surface, identity model,
     and authorization boundary.

## Removal conditions

V0 product code can be deleted when:

1. The target PostgreSQL foundation, tenancy, idempotency, lifecycle, and outbox tests pass.
2. The native JobSpec and S3 payload path pass payload-isolation and quote-immutability tests.
3. The target attempt model passes stale-generation, duplicate/conflicting output, partial failure, and canonicalization tests.
4. The local provider, deterministic engine, and fault harness operate through target interfaces.
5. Provider reconciliation and simultaneous/cumulative spend-envelope tests pass.
6. The customer portal, SDK, and CLI use only the target API.
7. The 72-hour flex customer journey is deployed and has passed the Milestone 8 qualification gate.
8. No current task, test, evidence procedure, or supported command depends on the v0 runtime.

The per-file Ruff exceptions in `pyproject.toml` are removed in the same change that deletes their v0 files.

## Consequences

- Target invariants are not weakened to accommodate a prototype schema or protocol.
- Useful local diagnostics remain available during replacement.
- There is no dual-write or customer-data migration problem.
- The customer portal cannot accidentally become an operator console or agent-management surface.
- The repository temporarily contains two execution shapes, so documentation and commands must label v0 explicitly.
- Later milestones must reproduce every retained v0 property as a target regression test before deletion.

## Rejected alternatives

### Harden v0 in place

Rejected because the state, payload, trust, and accounting authorities all change. Hardening mutable results or inline payload endpoints would build the wrong system more carefully.

### Delete v0 immediately

Rejected because the local provider, deterministic engine, fault phases, and characterized failure modes are valuable test assets while target execution is being built.

### Maintain both as supported products

Rejected because there is no customer compatibility requirement and two authorities would multiply security, accounting, and operational risk.
