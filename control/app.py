"""Control plane. Small on purpose: it holds all the state and all the decisions,
so that workers can be as stupid and as disposable as we need them to be."""

import os
import threading
import time

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from . import db

TOKEN = os.environ.get("FB_TOKEN", "dev-token")
LEASE_SECS = float(os.environ.get("FB_LEASE_SECS", 90))

app = FastAPI(title="firmbatch control plane")


def auth(authorization: str | None):
    if authorization != f"Bearer {TOKEN}":
        raise HTTPException(401, "bad token")


@app.on_event("startup")
def _startup():
    db.init()
    def reaper():
        while True:
            try:
                db.reap()
            except Exception as e:          # never let the reaper die
                print("reaper error:", e)
            time.sleep(5)
    threading.Thread(target=reaper, daemon=True).start()


# --------------------------------------------------------------- worker API

class Reg(BaseModel):
    worker_id: str
    job_id: str
    provider: str = "unknown"
    instance_id: str | None = None
    instance_type: str | None = None
    price_hr: float = 0.0


@app.post("/w/register")
def w_register(r: Reg, authorization: str = Header(None)):
    auth(authorization)
    db.register_worker(r.worker_id, r.job_id, r.provider, r.instance_id,
                       r.instance_type, r.price_hr)
    return {"ok": True, "lease_secs": LEASE_SECS}


class HB(BaseModel):
    worker_id: str
    shard_id: str | None = None


@app.post("/w/heartbeat")
def w_heartbeat(h: HB, authorization: str = Header(None)):
    auth(authorization)
    out = db.heartbeat(h.worker_id)
    if h.shard_id:
        db.extend_lease(h.shard_id, h.worker_id, LEASE_SECS)
    return out


class Claim(BaseModel):
    worker_id: str
    job_id: str


@app.post("/w/claim")
def w_claim(c: Claim, authorization: str = Header(None)):
    auth(authorization)
    job = db.get_job(c.job_id)
    if not job or job["status"] != "running":
        return {"shard": None, "stop": True}
    shard = db.claim(c.job_id, c.worker_id, LEASE_SECS)
    # `outstanding` includes shards currently leased to other workers. A worker
    # with nothing to claim must idle rather than exit while that is non-zero:
    # one of those leases may belong to a machine that has already been taken
    # away, and its shard is about to need a home.
    return {"shard": shard, "stop": False, "model": job["model"],
            "accept": job["accept_json"], "outstanding": db.outstanding(c.job_id)}


class Res(BaseModel):
    worker_id: str
    job_id: str
    shard_id: str
    results: list = []
    done: bool = False


@app.post("/w/results")
def w_results(r: Res, authorization: str = Header(None)):
    auth(authorization)
    n = db.put_results(r.job_id, r.shard_id, r.worker_id, r.results) if r.results else 0
    if r.done:
        db.finish_shard(r.shard_id, r.worker_id)
    else:
        db.extend_lease(r.shard_id, r.worker_id, LEASE_SECS)
    st = db.status(r.job_id)
    if st and st["remaining"] == 0 and st["status"] == "running":
        db.set_job_status(r.job_id, "done")
    return {"stored": n}


# --------------------------------------------------------------- operator API

class NewJob(BaseModel):
    name: str
    model: str
    deadline_ts: float
    shard_size: int = 200
    requests: list
    accept: dict = {}


@app.post("/jobs")
def new_job(j: NewJob, authorization: str = Header(None)):
    auth(authorization)
    return {"job_id": db.create_job(j.name, j.model, j.deadline_ts, j.shard_size,
                                    j.requests, j.accept)}


@app.get("/jobs/{job_id}")
def job_status(job_id: str, authorization: str = Header(None)):
    auth(authorization)
    st = db.status(job_id)
    if not st:
        raise HTTPException(404, "no such job")
    return st


@app.get("/jobs/{job_id}/output")
def job_output(job_id: str, authorization: str = Header(None)):
    auth(authorization)
    return {"results": db.outputs(job_id)}


@app.get("/jobs/{job_id}/ledger")
def job_ledger(job_id: str, authorization: str = Header(None)):
    auth(authorization)
    return db.ledger(job_id)


@app.get("/jobs/{job_id}/events")
def job_events(job_id: str, limit: int = 40, authorization: str = Header(None)):
    auth(authorization)
    return {"events": db.events(job_id, limit)}


@app.post("/jobs/{job_id}/cancel")
def job_cancel(job_id: str, authorization: str = Header(None)):
    auth(authorization)
    db.set_job_status(job_id, "cancelled")
    return {"ok": True}


@app.get("/agent.py")
def agent_source():
    """Workers curl this at boot, so there is exactly one copy of the agent and
    no image to rebuild when it changes."""
    from fastapi.responses import PlainTextResponse
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "worker", "agent.py")
    with open(path) as fh:
        return PlainTextResponse(fh.read(), media_type="text/x-python")


@app.get("/health")
def health():
    return {"ok": True}
