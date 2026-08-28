"""SQLite store for firmbatch.

The whole durability story lives here. Two invariants matter:

  1. A shard is *leased*, never assigned. If a worker stops heartbeating, its
     lease expires and the shard returns to the pool. Preemption is therefore
     not an error path -- it is the normal path.

  2. Results are keyed by (job_id, request_id) and upserted. A request
     processed twice is harmless, so a worker may die at any instant without
     corrupting the job.
"""

import json
import os
import sqlite3
import time
import uuid

DB_PATH = os.environ.get("FB_DB", "firmbatch.db")

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS jobs (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  model         TEXT NOT NULL,
  deadline_ts   REAL NOT NULL,
  created_ts    REAL NOT NULL,
  status        TEXT NOT NULL,          -- running | done | cancelled
  shard_size    INTEGER NOT NULL,
  n_requests    INTEGER NOT NULL,
  accept_json   TEXT NOT NULL           -- acceptance spec
);

CREATE TABLE IF NOT EXISTS shards (
  id            TEXT PRIMARY KEY,
  job_id        TEXT NOT NULL,
  idx           INTEGER NOT NULL,
  state         TEXT NOT NULL,          -- pending | leased | done
  lease_worker  TEXT,
  lease_exp_ts  REAL,
  attempts      INTEGER NOT NULL DEFAULT 0,
  done_ts       REAL
);
CREATE INDEX IF NOT EXISTS ix_shard_pick ON shards(job_id, state, idx);

CREATE TABLE IF NOT EXISTS requests (
  job_id        TEXT NOT NULL,
  request_id    TEXT NOT NULL,
  shard_id      TEXT NOT NULL,
  payload       TEXT NOT NULL,
  PRIMARY KEY (job_id, request_id)
);
CREATE INDEX IF NOT EXISTS ix_req_shard ON requests(shard_id);

CREATE TABLE IF NOT EXISTS results (
  job_id        TEXT NOT NULL,
  request_id    TEXT NOT NULL,
  shard_id      TEXT NOT NULL,
  output        TEXT NOT NULL,
  accepted      INTEGER NOT NULL,
  worker_id     TEXT NOT NULL,
  ts            REAL NOT NULL,
  PRIMARY KEY (job_id, request_id)
);
CREATE INDEX IF NOT EXISTS ix_res_time ON results(job_id, ts);

CREATE TABLE IF NOT EXISTS workers (
  id            TEXT PRIMARY KEY,
  job_id        TEXT NOT NULL,
  provider      TEXT NOT NULL,
  instance_id   TEXT,
  instance_type TEXT,
  price_hr      REAL NOT NULL DEFAULT 0,
  state         TEXT NOT NULL,          -- starting | running | dead
  started_ts    REAL NOT NULL,
  last_seen_ts  REAL,
  stopped_ts    REAL,
  stop_reason   TEXT
);

CREATE TABLE IF NOT EXISTS events (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            REAL NOT NULL,
  job_id        TEXT,
  worker_id     TEXT,
  kind          TEXT NOT NULL,
  detail        TEXT
);
"""


def conn():
    c = sqlite3.connect(DB_PATH, timeout=15, isolation_level=None)
    c.row_factory = sqlite3.Row
    return c


def init():
    with conn() as c:
        c.executescript(SCHEMA)


def log(c, kind, detail="", job_id=None, worker_id=None):
    c.execute(
        "INSERT INTO events(ts, job_id, worker_id, kind, detail) VALUES (?,?,?,?,?)",
        (time.time(), job_id, worker_id, kind, detail),
    )


# ---------------------------------------------------------------- jobs

def create_job(name, model, deadline_ts, shard_size, requests, accept):
    job_id = "job_" + uuid.uuid4().hex[:10]
    now = time.time()
    with conn() as c:
        c.execute("BEGIN IMMEDIATE")
        c.execute(
            "INSERT INTO jobs(id,name,model,deadline_ts,created_ts,status,shard_size,n_requests,accept_json)"
            " VALUES (?,?,?,?,?,'running',?,?,?)",
            (job_id, name, model, deadline_ts, now, shard_size, len(requests), json.dumps(accept)),
        )
        for i in range(0, len(requests), shard_size):
            chunk = requests[i : i + shard_size]
            shard_id = "shd_" + uuid.uuid4().hex[:10]
            c.execute(
                "INSERT INTO shards(id,job_id,idx,state) VALUES (?,?,?,'pending')",
                (shard_id, job_id, i // shard_size),
            )
            c.executemany(
                "INSERT INTO requests(job_id,request_id,shard_id,payload) VALUES (?,?,?,?)",
                [(job_id, r["request_id"], shard_id, json.dumps(r)) for r in chunk],
            )
        log(c, "job.created", f"{name} n={len(requests)}", job_id=job_id)
        c.execute("COMMIT")
    return job_id


def get_job(job_id):
    with conn() as c:
        r = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return dict(r) if r else None


def set_job_status(job_id, status):
    with conn() as c:
        c.execute("UPDATE jobs SET status=? WHERE id=?", (status, job_id))
        log(c, "job." + status, job_id=job_id)


def latest_job():
    with conn() as c:
        r = c.execute("SELECT id FROM jobs ORDER BY created_ts DESC LIMIT 1").fetchone()
        return r["id"] if r else None


# ---------------------------------------------------------------- leases

def reap(now=None):
    """Return expired leases to the pool. Safe to call constantly."""
    now = now or time.time()
    with conn() as c:
        c.execute("BEGIN IMMEDIATE")
        rows = c.execute(
            "SELECT id, job_id, lease_worker FROM shards WHERE state='leased' AND lease_exp_ts < ?",
            (now,),
        ).fetchall()
        for r in rows:
            c.execute(
                "UPDATE shards SET state='pending', lease_worker=NULL, lease_exp_ts=NULL WHERE id=?",
                (r["id"],),
            )
            log(c, "lease.expired", r["id"], job_id=r["job_id"], worker_id=r["lease_worker"])
        c.execute("COMMIT")
    return len(rows)


def claim(job_id, worker_id, lease_secs):
    """Lease the lowest-index outstanding shard and return only the requests
    that do not already have a result. Re-claiming a partially finished shard
    therefore costs only the unfinished remainder."""
    now = time.time()
    with conn() as c:
        c.execute("BEGIN IMMEDIATE")
        row = c.execute(
            "SELECT id FROM shards WHERE job_id=? AND state='pending' ORDER BY idx LIMIT 1",
            (job_id,),
        ).fetchone()
        if not row:
            c.execute("COMMIT")
            return None
        shard_id = row["id"]
        c.execute(
            "UPDATE shards SET state='leased', lease_worker=?, lease_exp_ts=?, attempts=attempts+1"
            " WHERE id=?",
            (worker_id, now + lease_secs, shard_id),
        )
        pending = c.execute(
            "SELECT r.payload FROM requests r"
            " LEFT JOIN results o ON o.job_id=r.job_id AND o.request_id=r.request_id"
            " WHERE r.shard_id=? AND o.request_id IS NULL",
            (shard_id,),
        ).fetchall()
        log(c, "shard.leased", f"{shard_id} n={len(pending)}", job_id=job_id, worker_id=worker_id)
        c.execute("COMMIT")

    if not pending:                       # already fully answered by an earlier attempt
        finish_shard(shard_id, worker_id)
        return claim(job_id, worker_id, lease_secs)
    return {"shard_id": shard_id, "requests": [json.loads(p["payload"]) for p in pending]}


def extend_lease(shard_id, worker_id, lease_secs):
    with conn() as c:
        c.execute(
            "UPDATE shards SET lease_exp_ts=? WHERE id=? AND lease_worker=? AND state='leased'",
            (time.time() + lease_secs, shard_id, worker_id),
        )


def finish_shard(shard_id, worker_id):
    with conn() as c:
        c.execute(
            "UPDATE shards SET state='done', done_ts=?, lease_worker=NULL, lease_exp_ts=NULL"
            " WHERE id=?",
            (time.time(), shard_id),
        )
        log(c, "shard.done", shard_id, worker_id=worker_id)


# ---------------------------------------------------------------- results

def put_results(job_id, shard_id, worker_id, rows):
    """Idempotent. rows = [{request_id, output, accepted}]"""
    now = time.time()
    with conn() as c:
        c.execute("BEGIN IMMEDIATE")
        c.executemany(
            "INSERT INTO results(job_id,request_id,shard_id,output,accepted,worker_id,ts)"
            " VALUES (?,?,?,?,?,?,?)"
            " ON CONFLICT(job_id,request_id) DO UPDATE SET"
            "   output=excluded.output, accepted=excluded.accepted,"
            "   worker_id=excluded.worker_id, ts=excluded.ts",
            [
                (job_id, r["request_id"], shard_id, json.dumps(r["output"]),
                 1 if r.get("accepted") else 0, worker_id, now)
                for r in rows
            ],
        )
        c.execute("COMMIT")
    return len(rows)


def outputs(job_id):
    with conn() as c:
        return [
            {"request_id": r["request_id"], "output": json.loads(r["output"]),
             "accepted": bool(r["accepted"])}
            for r in c.execute(
                "SELECT request_id, output, accepted FROM results WHERE job_id=? ORDER BY request_id",
                (job_id,),
            )
        ]


# ---------------------------------------------------------------- workers

def register_worker(worker_id, job_id, provider, instance_id, instance_type, price_hr):
    with conn() as c:
        c.execute(
            "INSERT INTO workers(id,job_id,provider,instance_id,instance_type,price_hr,state,started_ts,last_seen_ts)"
            " VALUES (?,?,?,?,?,?,'starting',?,?)"
            " ON CONFLICT(id) DO UPDATE SET instance_id=excluded.instance_id,"
            "   instance_type=excluded.instance_type, price_hr=excluded.price_hr",
            (worker_id, job_id, provider, instance_id, instance_type, price_hr,
             time.time(), time.time()),
        )
        log(c, "worker.launched", f"{instance_type} @ ${price_hr}/h",
            job_id=job_id, worker_id=worker_id)


def heartbeat(worker_id):
    with conn() as c:
        c.execute(
            "UPDATE workers SET last_seen_ts=?, state='running' WHERE id=? AND state!='dead'",
            (time.time(), worker_id),
        )
        r = c.execute("SELECT job_id FROM workers WHERE id=?", (worker_id,)).fetchone()
        if not r:
            return {"stop": True}
        j = c.execute("SELECT status FROM jobs WHERE id=?", (r["job_id"],)).fetchone()
        return {"stop": bool(j and j["status"] != "running")}


def kill_worker(worker_id, reason):
    """Marks the worker dead AND returns its shards to the pool at once.

    Lease expiry is the backstop for when this controller is itself dead; it
    should never be the primary recovery path, because every second a shard
    sits leased to a corpse is a second of paid capacity with nothing to do.
    """
    with conn() as c:
        c.execute("BEGIN IMMEDIATE")
        c.execute(
            "UPDATE workers SET state='dead', stopped_ts=?, stop_reason=? WHERE id=?",
            (time.time(), reason, worker_id),
        )
        freed = c.execute(
            "SELECT id, job_id FROM shards WHERE lease_worker=? AND state='leased'",
            (worker_id,),
        ).fetchall()
        c.execute(
            "UPDATE shards SET state='pending', lease_worker=NULL, lease_exp_ts=NULL"
            " WHERE lease_worker=? AND state='leased'",
            (worker_id,),
        )
        log(c, "worker.dead", f"{reason} (released {len(freed)} shard(s))",
            job_id=freed[0]["job_id"] if freed else None, worker_id=worker_id)
        c.execute("COMMIT")
    return len(freed)


def worker_has_lease(worker_id):
    with conn() as c:
        r = c.execute(
            "SELECT COUNT(*) n FROM shards WHERE lease_worker=? AND state='leased'",
            (worker_id,),
        ).fetchone()
        return r["n"] > 0


def outstanding(job_id):
    """Shards not yet done -- pending or leased. A worker must not go home
    while this is non-zero, because a leased shard may still come back."""
    with conn() as c:
        r = c.execute(
            "SELECT COUNT(*) n FROM shards WHERE job_id=? AND state!='done'", (job_id,)
        ).fetchone()
        return r["n"]


def live_workers(job_id):
    with conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM workers WHERE job_id=? AND state!='dead' ORDER BY started_ts", (job_id,))]


def all_workers(job_id):
    with conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM workers WHERE job_id=? ORDER BY started_ts", (job_id,))]


# ---------------------------------------------------------------- status

def status(job_id):
    job = get_job(job_id)
    if not job:
        return None
    now = time.time()
    with conn() as c:
        n_done = c.execute("SELECT COUNT(*) n FROM results WHERE job_id=?", (job_id,)).fetchone()["n"]
        n_acc = c.execute(
            "SELECT COUNT(*) n FROM results WHERE job_id=? AND accepted=1", (job_id,)
        ).fetchone()["n"]
        shards = {r["state"]: r["n"] for r in c.execute(
            "SELECT state, COUNT(*) n FROM shards WHERE job_id=? GROUP BY state", (job_id,))}
        recent = c.execute(
            "SELECT COUNT(*) n FROM results WHERE job_id=? AND ts > ?", (job_id, now - 120)
        ).fetchone()["n"]

    rate = recent / 120.0                                   # accepted+rejected per second
    remaining = job["n_requests"] - n_done
    eta = (remaining / rate) if rate > 0 else None
    return {
        "job_id": job_id,
        "name": job["name"],
        "status": job["status"],
        "model": job["model"],
        "n_requests": job["n_requests"],
        "completed": n_done,
        "accepted": n_acc,
        "remaining": remaining,
        "shards": {"pending": shards.get("pending", 0), "leased": shards.get("leased", 0),
                   "done": shards.get("done", 0)},
        "rate_per_s": round(rate, 3),
        "eta_s": round(eta) if eta is not None else None,
        "deadline_ts": job["deadline_ts"],
        "seconds_to_deadline": round(job["deadline_ts"] - now),
        "on_track": (eta is not None and now + eta <= job["deadline_ts"]) if remaining else True,
        "workers_live": len(live_workers(job_id)),
    }


def ledger(job_id):
    """Realised cost per accepted output -- the only number that goes in a quote."""
    job = get_job(job_id)
    st = status(job_id)
    rows = all_workers(job_id)
    now = time.time()
    total = 0.0
    per_worker = []
    for w in rows:
        end = w["stopped_ts"] or now
        hours = max(0.0, (end - w["started_ts"]) / 3600.0)
        # Verda bills in pre-paid 10-minute increments -- round up to match the invoice.
        billed_h = (int(hours * 6) + 1) / 6.0
        cost = billed_h * w["price_hr"]
        total += cost
        per_worker.append({
            "worker": w["id"], "instance_type": w["instance_type"], "price_hr": w["price_hr"],
            "wall_h": round(hours, 4), "billed_h": round(billed_h, 4), "cost": round(cost, 4),
            "stop_reason": w["stop_reason"] or "-",
        })
    acc = st["accepted"] if st else 0
    return {
        "job_id": job_id, "name": job["name"] if job else None,
        "workers": per_worker,
        "total_cost": round(total, 4),
        "accepted": acc,
        "cost_per_1k_accepted": round(total / acc * 1000, 6) if acc else None,
        "cost_per_1m_accepted": round(total / acc * 1_000_000, 4) if acc else None,
    }


def events(job_id, limit=40):
    with conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM events WHERE job_id=? OR worker_id IN"
            " (SELECT id FROM workers WHERE job_id=?) ORDER BY id DESC LIMIT ?",
            (job_id, job_id, limit))][::-1]
