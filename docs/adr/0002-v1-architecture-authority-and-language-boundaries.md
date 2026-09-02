# ADR 0002: v1 architecture authority and language boundaries

- **Status:** Accepted
- **Date:** 2026-09-02
- **Decision owners:** Firmbatch product owner and maintainers
- **Supersedes:** Product-direction claims in `docs/firmbatch-pilot-roadmap.md`

## Context

The repository's existing pilot roadmap predates revision C of the Firmbatch v1 target architecture. It contains useful engineering analysis, but some product sequencing and architecture claims no longer describe the intended product.

The approved source architecture defines a Python control plane, a native operator-side capacity agent, and an OCI execution worker. The product also requires a customer-facing authenticated application and billing path so a customer can progress from signup to an invoiced batch job without entering supplier or internal operational interfaces.

Without a recorded authority order and language boundary, implementation agents could continue the old roadmap, overgeneralize the current Python prototype, or introduce C++ because the inference stack contains native dependencies.

## Decision

1. `docs/architecture/v1-target-architecture.md` is the canonical repository implementation specification for the target described by `firmbatch_v1_target_architecture_3.pdf`, revision C, 1 September 2026.
2. `docs/firmbatch-v1-roadmap.md` is the canonical implementation sequence from the current v0 prototype to that target, including customer accounts, portal, and billing.
3. `docs/STATE.md` remains authoritative for what the code does now. Target and roadmap documents never prove that a capability is implemented.
4. The old `docs/firmbatch-pilot-roadmap.md` is retained as historical design context and marked superseded. It is not an executable implementation plan.
5. The public surfaces are separated:
   - `firmbatch.com`: public marketing and documentation.
   - `app.firmbatch.com`: customer identity, workspaces, billing, jobs, results, and invoices.
   - `api.firmbatch.com`: native customer API used by the portal, SDK, CLI, and automation.
   - Supplier and internal operations use distinct identities, permissions, and interfaces.
6. Implementation-language boundaries are:
   - **Control plane:** Python, one image with API, controller/reconciler, and validator/canonicalizer roles.
   - **Operator capacity agent:** one small, static **Rust or Go** binary. The final Rust-versus-Go selection is deferred until the Milestone 6 design review evaluates operator environments, scheduler integrations, binary distribution, security review, and team maintenance cost.
   - **Execution worker:** signed, digest-pinned OCI image. Python may orchestrate the worker and vLLM. Upstream CUDA/C++ dependencies are acceptable inside the image.
   - **Customer web:** TypeScript is the default implementation recommendation, not a constraint from the target architecture.
7. Firmbatch-authored C++ is not required for v1. A custom native runtime requires a later ADR supported by profiling evidence that the registered inference engine cannot meet a target property.

## Consequences

- Agents can review and diff the target without re-extracting a PDF.
- Current-state documentation, target architecture, and implementation sequence have separate meanings and cannot silently overwrite one another.
- The Python prototype can contribute measured behavior and concepts without forcing its interfaces or storage model into v1.
- The operator agent can be implemented as a portable, outbound-only artifact without placing customer payload or long-lived Firmbatch credentials in an operator cluster.
- C++ does not enter the critical path merely because vLLM and GPU libraries contain native code.
- The Rust-versus-Go choice remains a deliberate, bounded decision rather than an accidental first implementation.

## Follow-up decision gate for the operator agent

Before implementation, compare Rust and Go against:

- Static binary and cross-compilation support for actual operator environments.
- Kubernetes and scheduler client maturity required by the first integration.
- Cryptographic signing and credential-handling libraries.
- Memory safety and attack-surface review.
- Upgrade, rollback, and support burden.
- Team familiarity and on-call debugging cost.
- Binary size and cold-start constraints, if measured to matter.

Choose one language for v1 and record it in a focused ADR. Do not maintain two implementations.
