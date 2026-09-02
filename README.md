# firmbatch

> [!IMPORTANT]
> **Current code:** v0 prototype. **Target:** Firmbatch v1 revision C.
>
> The canonical target is `docs/architecture/v1-target-architecture.md`.
> The implementation sequence is `docs/firmbatch-v1-roadmap.md`.

A persistent batch job that survives its machines.

The customer buys one durable obligation — *this quantity of accepted output, by
this deadline, for this price*. Underneath, machines are rented, used, killed and
replaced. The job never notices. That property is the entire product, and it is
about 900 lines of Python.

```
  PERSISTENT JOB  ─ accepted 3,850 / 4,000 · deadline 18:00 · validator v1
        │
        ├── run A  supplier 1  preempted        ← shards returned to the pool
        ├── run B  supplier 2  running
        ├── run C  supplier 3  provisioning
        └── run D  reserve     held
```

---

## Prove it locally first — no account, no GPU, no money

```bash
pip install fastapi uvicorn pydantic requests
cd <parent-of-firmbatch>
export FB_TOKEN=dev-token

python3 -m firmbatch.fb serve &                 # control plane on :8080
python3 -m firmbatch.fb demo --n 4000 --deadline +3m --chaos-n 3
```

`demo` submits 4,000 requests, launches workers, hard-kills some of them
mid-flight with `SIGKILL`, and prints the run's completion, deadline, and cost
per million accepted outputs.

### What the captured run actually shows

One local run is preserved as evidence. On an echo engine, with subprocess
workers on one machine, at fake prices:

| Observed | Value |
| --- | --- |
| Requests completed | 4,000 / 4,000 accepted |
| Requests with no result | 0 |
| Shards marked done while still missing a result | 0 |
| Results attributed to the wrong shard | 0 |
| Shards re-leased after their worker was released | 3, each on attempt 2 of 2 |
| Cost per million accepted | **$26.67** |

A duplicate-result count is deliberately not listed: `results` is keyed
`PRIMARY KEY (job_id, request_id)` and upserted, so distinct ids can never exceed rows.
It would read zero on a broken implementation too. Double processing is harmless and
invisible **by design** — that is the idempotency invariant working, not a measurement.

Artifacts: [`local-demo-001-report.txt`](docs/evidence/v0/local-demo-001-report.txt),
[`local-demo-001-reconciliation.json`](docs/evidence/v0/local-demo-001-reconciliation.json),
[`local-demo-001-environment.txt`](docs/evidence/v0/local-demo-001-environment.txt).

So the re-lease path is observed, and for this run the output rows reconcile at the row
level.

Note what that does *not* say. The artifact records that three shards were claimed twice;
it does not record whether the second claim carried any requests, because a re-claim that
finds nothing left also produces `attempts: 2`. The distinguishing detail is logged but
not preserved in the artifact. And row-level reconciliation is narrower than accounting
correctness — the artifact says so itself: *"Conflicting retry outputs cannot be
reconstructed because v0 overwrites the previous result for each request_id."* That
limitation applies to exactly the three retried shards above. Request-level accounting
correctness is NOT VERIFIED.

These artifacts are **HISTORICAL**: two of the three carry no provenance header, so their
capture commit is not recoverable from the files themselves.

### What that run does not show

**Recovery from a genuine unannounced preemption is NOT VERIFIED.** Every worker
in the captured run stopped as `job_complete` or `scaled_down` — the controller's
own release path. No `no_heartbeat` stop reason and no `lease.expired` event
appear anywhere in it, and those are the only records an unannounced kill leaves.
`fb chaos` writes no kill record to the database, so the kill is visible on stdout
alone, and that output was not captured. The three re-leases above are fully
explained by the orderly scale-downs.

**The deadline verdict is NOT VERIFIED.** No captured artifact records whether the
deadline was met.

The `$26.67` is a real number from a real run, but it is an echo engine on local
subprocesses at a hardcoded fake price. It is not a quotable figure for GPU
supply, and no v0 result is pilot-ready customer proof.

[`docs/STATE.md`](docs/STATE.md) is the canonical record of what is CURRENT,
VERIFIED LIVE, HISTORICAL, and NOT VERIFIED, and carries the v0 defect register.

Run the property tests directly:

```bash
python3 -m firmbatch.tests.test_recovery
```

---

## The two invariants

Everything else is plumbing. These two are the product.

**1 · Shards are leased, never assigned.** A worker holds a shard for
`FB_LEASE_SECS`, extended by every heartbeat. Stop heartbeating and the shard
returns to the pool. Preemption is therefore not an error path — it is the
normal path, exercised on every run.

Two mechanisms, deliberately: the controller releases a dead worker's shards the
moment it notices the missing heartbeat, and lease expiry catches the case where
the controller itself has died. Relying on expiry alone costs you a minute of
paid capacity doing nothing, every time.

**2 · Results are keyed by `(job_id, request_id)` and upserted.** A request
processed twice is harmless. Workers post results in chunks of 25 *as they go*,
so a machine killed between two lines has already banked everything it finished.
When a shard is re-claimed the control plane sends only the requests with no
result yet — a preemption at 60% costs you the remaining 40%, not the shard.

---

## Going to Verda

Confirmed against SDK 1.24.1. Verda is the right first supplier: real REST API,
Python SDK, published spot tier at half the on-demand rate on every SKU, and
datacentres in Finland (`FIN-01/02/03`) and Iceland (`ICE-01`).

### 1 · Credentials and a reachable control plane

```bash
pip install verda
cp .env.example .env          # VERDA_CLIENT_ID / VERDA_CLIENT_SECRET
```

Workers must reach the control plane over the public internet. Pick one:

* **Day one:** `cloudflared tunnel --url http://localhost:8080` and use the
  URL it prints as `--ctl-url`.
* **Anything real:** a €5/month VPS, or a Verda CPU instance so there is one
  bill and one network.

### 2 · Find out what actually exists

```bash
python3 -m firmbatch.fb probe --check
```

Lists every instance type with its price and whether spot capacity is available
right now. Do not hardcode instance-type names from a webpage — ask the API.
Start with the cheapest single-GPU box that fits your model, not an H100.

### 3 · Run it

```bash
python3 -m firmbatch.fb submit --file work.jsonl --model Qwen/Qwen3-4B-Instruct \
    --deadline +45m --shard-size 200 \
    --accept '{"type":"labels","labels":["positive","negative","neutral"]}'

python3 -m firmbatch.fb run --provider verda --engine vllm \
    --instance-type 1L40S.20V --location FIN-03 --max-workers 4 \
    --ctl-url https://your-tunnel.example
```

The controller creates one startup script per job, then launches spot instances
whose hostname *is* the worker id. Each box curls `agent.py` from your control
plane and runs it under systemd — so there is exactly one copy of the agent and
no image to rebuild when you change it.

In a separate shell, the demo that matters:

```bash
python3 -m firmbatch.fb watch
python3 -m firmbatch.fb chaos --n 2      # delete two live instances outright
python3 -m firmbatch.fb report
```

---

## What will actually cost you a day

* **Model load dominates a short-lived worker.** Boot + CUDA + weight download
  can be 6–12 minutes. A worker preempted 20 minutes in has spent half its life
  getting ready. Bake weights into a snapshot before you draw any conclusion
  about whether spot is cheap.
* **Verda bills in pre-paid 10-minute increments.** The ledger already rounds up
  to match the invoice. A worker that lives 90 seconds still costs ten minutes,
  which is why the controller does not thrash.
* **Preemption notice is undocumented.** Assume zero. Measure it, and put the
  answer in your supply book — it is question 2 of the RFQ.
* **Delete volumes with the instance.** `kill()` passes
  `delete_permanently=True`. An orphaned OS volume is a bill that arrives after
  you have forgotten the experiment.
* **Set a spend ceiling before the first overnight run.** `--max-workers` is the
  only thing between a controller bug and a four-figure invoice.

---

## Layout

```
control/db.py        leases, idempotent results, ledger      ~330 lines
control/app.py       FastAPI: worker API + operator API      ~170
controller.py        the deadline loop                       ~120
providers/local.py   subprocess workers, for testing          ~50
providers/verda.py   Verda adapter + bootstrap script        ~150
worker/agent.py      standalone, requests-only, disposable   ~200
fb.py                CLI: serve submit run watch chaos report ~220
tests/               the invariants, deterministically         ~110
```

## Deliberately absent

No marketplace UI. No underwriting engine — a spreadsheet, for now. No Merkle
anchoring, no certification grades, no multi-tenancy, no billing, no custom
inference runtime, no training. Inference only, one provider at a time, until
three customers have paid.
