# Architecture source snapshots and reviewed authorities

This directory holds the **supplied architecture source documents** behind the canonical
target, preserved byte for byte so that a later reader can check what the canonical rendering
was derived from, and this manifest records **every authority the Milestone 3.0 adoption
reviewed**, with its SHA-256 and whether it is stored here or only hash-referenced. The
canonical, numbered specification is `docs/architecture/v1-target-architecture.md`; **nothing in
this directory is authoritative over it**, and nothing here is evidence that anything is
implemented.

## Current authority: revision D.1

| File | What it is | Stored here | SHA-256 |
| --- | --- | --- | --- |
| `architecture-v1-rev-d-1.md` | The supplied **rev D.1** Markdown, `architecture-v1_4.md` (6 September 2026, 581 lines), copied verbatim on 2026-09-06. **This is the current source.** | yes | `44e29e0761a2f82f799448622e328dfaa9c8e53c594c6fe0d7962d9c0f5853f3` |
| `firmbatch_v1_target_architecture_5.pdf` | The rev D.1 companion PDF, 12 pages | no — hash-referenced | `45a605424701badaa8ff3b4591d87659f70313ab758d20e2b0c658078a8a6220` |

Rev D.1 is rev D plus the resolution of the ten review items the rev D adoption had carried
as open (`docs/architecture/rev-d-decision-register.md`), in every case by taking the
settlement canon, plan v3.4 or roadmap r2_4 as the authority, and plus the internal
**qualification** service tier.

## Historical reviewed input: revision D

| File | What it is | Stored here | SHA-256 |
| --- | --- | --- | --- |
| `architecture-v1-rev-d.md` | The supplied **rev D** Markdown, `architecture-v1_3.md` (6 September 2026, 497 lines), copied verbatim on 2026-09-06. Superseded by D.1 the same day, before this branch was committed. Kept as the input the D review was made against; **not current authority**. | yes | `ea09cb2eb0c4c7f0a9e065b13d0630833019935a3b496bc12006486757da2a2c` |
| `firmbatch_v1_target_architecture_4.pdf` | The rev D companion PDF, 11 pages | no — hash-referenced | `c2ebd560ca70ac0f3be22794b1cc3387ab61678cf18a9db8e434bb89cdff35e3` |

The rev C source, `firmbatch_v1_target_architecture_3.pdf` (1 September 2026), was never
stored; its rendering is the canonical target as it stood before the Milestone 3.0 adoption,
recoverable from git history.

The rev D snapshot is **not** the D.1 content under another name, and the D.1 snapshot is not
a relabelled D. Diff the two files to see what D.1 changed; the canonical target's §18 lists
it by section.

## Companion authorities reviewed for the D.1 adoption

Supplied under `canon/` beside the D.1 sources and read in full for this adoption. None is
stored in the repository; each is identified by hash so a later reader can confirm they are
looking at the same document. Where the canonical target cites one, it cites the section.

| Document | Role | SHA-256 |
| --- | --- | --- |
| `settlement-model-r1_3.md` — supplier settlement model r1, Amendments 1–4 | **Canonical for settlement.** Where the architecture and this file disagree, this file is right. Source of the cancellation-cause enum, payability and revocation columns, the once-per-operator-month `max`, the 90-day true-up and the settlement timing. | `7e124382d567067e4b37576e8ad6da10edb05c7ae956199240c8197fac8afaea` |
| `firmbatch_plan_v3_4.pdf` — working plan v3.4, 3 September 2026 (15 pages) | Phase 0 (the merchant bridge), the three bridge caps and their planning amounts, gate order 0 → 1 → 3 → 2, Gate 1 and Gate 2 deliverables and kill conditions, the firm tier definition, compliance layers. | `83493902c0a185580918ffa82c344a27ea764710081e101909ad1be34f5ad207` |
| `firmbatch-pilot-roadmap-r2_4.md` — pilot roadmap revision 4 | Business phases D, P, S; invariants 1–30; D4 evaluation harness (the definition of the escalation rate `x`); D5 production bridge; P4 cash rules; census questions T8/T9. Note: its invariant 21 still says only two operator-side causes revoke a window; the canon's table and rev D.1 also revoke on an operator-asserted `security_stop`, and the canon wins. | `16f0846d2c08267eb479b47c6a53fd83b9fa068d3ee5a5eb88d363e63433b8cf` |
| `gpu_price_register_1.xlsx` — GPU price register revision 1, 5 September 2026 | The versioned price register: hyperscaler spot and on-demand by region and SKU (Google 30 Aug, AWS 3 Sep, Azure 3–5 Sep 2026), neocloud posted prices, transacted and listing indices, model-fit table, assumptions (`η_delivery` 0.9, `o_ctrl` $0.18) and a Sources sheet resolving every row's source key. One-day snapshots with a `Captured` date; not fill rates. | `5355f131501343f655355675b21914c1f61d1e4bebbd6889a07b6441523db88f` |
| `firmbatch_customer_brief_2.pdf` — customer brief revision 2 (5 pages) | The evaluation offer (1,000 real requests and the customer's rules; no charge, no commitment), accepted-unit billing, the two tiers, the acceptance-policy rule types, what a pilot needs from the customer. | `8be26b2128df27ca18e71ebccaaeb5857672fe735916e6b52906505fafc3ce8d` |
| `firmbatch_definitions_4.pdf` — the numbers in plain language, revision 4 (13 pages) | Every symbol with its grade (derived, market, published, assumed, to measure, decision); the assumption register, including the bridge budget cap as a *decision* and `f_c` as *to measure*. | `06eb1b1bff5babb9eb4ff5013e7f0f3e1903eb5b1a9f141f580388261e2597da` |
| `firmbatch_demand_alternatives_3.pdf` — demand risk and alternative schemes, revision 3 (6 pages) | The supply stack (rungs 1–4), the endpoint layer as a permitted fast lane that never passes Gate 2, node windows, the escalation-rate hybrid formula, the decision table. | `dc518b8c863a30206bff407cde87d6c8c9ee5f155491014c90b81aaef5ad5870` |
| `firmbatch_operator_equation_2.pdf` — the operator's equation, revision 2 (13 pages) | Why the GPU price is regional and the cost is not; Google's regional spot list (§6.3); how Phase 0 should use it (§6.4). | `6a47cc033d062599a559d97e2f570a6c559f488f07a5a4fea755db0f7ad8f323` |
| `rfq_interruptible_gpu_capacity_2.pdf` — RFQ revision 2 (13 pages) | The operator RFQ: structures A and B, Q1–Q9, T1–T10, S1–S5, Annexes A–D (definitions, settlement table, `W_min`, response sheet). | `b7df7aaccb5e038652ef92d1dd7c3b4c8d8e33c4410b4f63e26959f94f900ab7` |
| `rfq_interruptible_gpu_capacity_2.docx` | The same RFQ as an editable document | `c770e26ca28ff927bb721dc1f5ae50c41470e6a504ee2059f81c3069d79f9bb6` |
| `rfq_endpoint_capacity_1.pdf` — endpoint RFQ revision 1 (2 pages) | The endpoint-supplier variant: share of NCR or a per-million-token price for droppable batch traffic, drop signal, per-request usage records. | `d4869205b1574898917da3e4aaf778819979bba8a9a422b89bc1477584d58c5b` |
| `rfq_endpoint_capacity_1.docx` | The same endpoint RFQ as an editable document | `8dc36eed6f252879eadef3a11ba07c703d5883301b9e28d1433b61f549989bd6` |

## Rules for this directory

- **A snapshot is immutable.** It is a copy of a document somebody else authored. Correct a
  wrong rendering in the canonical file, never by editing the snapshot. A new revision gets
  a new file, never an overwrite.
- **Verify before relying on it.** `sha256sum docs/architecture/sources/*.md` must print the
  hashes in the tables above. A mismatch means the snapshot is not the reviewed source and
  the canonical rendering must be re-checked against the original.
- **The snapshot's own status banner is the source's, not the repository's.** Both rev D and
  rev D.1 open with "Status: PLANNED. Nothing here is implemented". That is the *target
  document's* disclaimer about itself: it describes what v1 must become and claims nothing
  about implementation. It is **not** a statement about this repository, and it does not
  erase the merged Milestone 2 foundation (PostgreSQL spine, tenant isolation, idempotency,
  outbox, authenticated context, audit, secrets model, lifecycle kernel). `docs/STATE.md` is
  the only record of what the code does; read the two together.
- **Source content authorizes nothing.** The companions inform the canonical documentation;
  they do not authorize deployment, purchases, supplier contact, customer invitations or
  payments. Prices, SKUs, regions, quotas, notice periods and cost examples in any of these
  documents are the documents' figures at their capture dates (the price register says
  which); they are not deployable configuration, not verified market data, and not a
  spending approval. Cloud purchases, deployment and supplier contact remain human-owned
  actions under `AGENTS.md`.
- **Planning ranges are not configured caps.** Plan v3.4 carries the bridge budget as a
  planning range ($3–5k a month net of billings, $10k in total) and the definitions register
  grades it a *decision*. The exact cap and per-supplier sub-caps that will be configured are
  deployment and spend decisions recorded on the envelope by a human before the first
  purchase; no document in this repository fixes them.
