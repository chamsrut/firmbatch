#!/usr/bin/env python3
"""Deterministic tests for the properties the whole business rests on.

    python3 -m firmbatch.tests.test_recovery
"""
import os, sys, tempfile, time

os.environ["FB_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")
from firmbatch.control import db   # noqa: E402

FAIL = []


def check(name, cond, extra=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}{('  ' + extra) if extra else ''}")
    if not cond:
        FAIL.append(name)


def reqs(n, off=0):
    return [{"request_id": f"r{i+off:05d}", "prompt": f"p{i+off}"} for i in range(n)]


def main():
    db.init()

    # ---- 1. a lease expires and the shard comes back -----------------------
    j = db.create_job("t1", "m", time.time() + 600, 10, reqs(30), {"type": "any"})
    got = db.claim(j, "w1", lease_secs=-1)                 # already expired
    check("claim returns a shard", got is not None)
    freed = db.reap()
    check("expired lease is reaped", freed == 1)
    check("shard is claimable again", db.claim(j, "w2", 60) is not None)

    # ---- 2. a dead worker's shards are released immediately ----------------
    j = db.create_job("t2", "m", time.time() + 600, 10, reqs(30), {"type": "any"})
    a = db.claim(j, "wA", 3600)                            # long lease: expiry cannot save us
    check("worker holds a lease", db.worker_has_lease("wA"))
    n = db.kill_worker("wA", "no_heartbeat")
    check("kill_worker releases the lease at once", n == 1)
    check("worker no longer holds a lease", not db.worker_has_lease("wA"))
    b = db.claim(j, "wB", 60)
    check("another worker gets that exact shard", b and b["shard_id"] == a["shard_id"],
          f"{a['shard_id']}")

    # ---- 3. partial work survives; only the remainder is re-issued ---------
    j = db.create_job("t3", "m", time.time() + 600, 100, reqs(100), {"type": "any"})
    c1 = db.claim(j, "wC", 3600)
    check("first claim gets all 100", len(c1["requests"]) == 100)
    part = [{"request_id": r["request_id"], "output": "ok", "accepted": True}
            for r in c1["requests"][:60]]
    db.put_results(j, c1["shard_id"], "wC", part)          # 60 done, then the machine dies
    db.kill_worker("wC", "preempted")
    c2 = db.claim(j, "wD", 3600)
    check("re-claim re-issues only the unfinished 40", len(c2["requests"]) == 40,
          f"got {len(c2['requests'])}")
    ids = {r["request_id"] for r in c2["requests"]}
    check("no already-answered request is re-issued",
          not (ids & {p["request_id"] for p in part}))

    # ---- 4. results are idempotent ----------------------------------------
    db.put_results(j, c1["shard_id"], "wD", part)          # replay the same 60
    db.put_results(j, c1["shard_id"], "wD", part)
    st = db.status(j)
    check("duplicate submissions do not double-count", st["completed"] == 60,
          f"completed={st['completed']}")

    # ---- 5. a fully-answered shard closes without redoing work -------------
    rest = [{"request_id": r["request_id"], "output": "ok", "accepted": True}
            for r in c2["requests"]]
    db.put_results(j, c2["shard_id"], "wD", rest)
    db.kill_worker("wD", "preempted")
    c3 = db.claim(j, "wE", 60)
    check("no work left to claim once every request has a result", c3 is None)
    check("job reports 100/100 complete", db.status(j)["completed"] == 100)

    # ---- 6. the ledger rounds up to the supplier's billing increment -------
    j = db.create_job("t4", "m", time.time() + 600, 10, reqs(10), {"type": "any"})
    db.register_worker("wF", j, "verda", "i-1", "1L40S", 1.19)
    time.sleep(0.05)
    db.kill_worker("wF", "job_complete")
    led = db.ledger(j)
    check("a 3-second worker is billed as 10 minutes",
          abs(led["workers"][0]["billed_h"] - 1 / 6) < 1e-3,   # ledger rounds to 4dp
          f"billed_h={led['workers'][0]['billed_h']:.4f}")

    print()
    if FAIL:
        print(f"  {len(FAIL)} FAILED: {FAIL}")
        sys.exit(1)
    print("  all checks passed")


if __name__ == "__main__":
    main()
