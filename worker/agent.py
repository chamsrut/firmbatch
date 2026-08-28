#!/usr/bin/env python3
"""firmbatch worker agent.

Deliberately stupid and standalone: one file, `requests` its only hard
dependency, no knowledge of other workers, no local state worth preserving.
It may be SIGKILLed between any two lines. Everything it has finished is
already on the control plane, because results are posted in small chunks as
they are produced rather than at the end of the shard.
"""

import json
import os
import random
import socket
import sys
import threading
import time
import uuid

import requests

URL       = os.environ["FB_URL"].rstrip("/")
TOKEN     = os.environ["FB_TOKEN"]
JOB       = os.environ["FB_JOB"]
WORKER_ID = os.environ.get("FB_WORKER_ID") or ("w-" + socket.gethostname()[-8:] or uuid.uuid4().hex[:8])
ENGINE    = os.environ.get("FB_ENGINE", "echo")
MODEL     = os.environ.get("FB_MODEL", "echo-model")
PROVIDER  = os.environ.get("FB_PROVIDER", "unknown")
PRICE_HR  = float(os.environ.get("FB_PRICE_HR", "0"))
ITYPE     = os.environ.get("FB_INSTANCE_TYPE", "unknown")

CHUNK          = int(os.environ.get("FB_CHUNK", "25"))
HEARTBEAT_SECS = float(os.environ.get("FB_HEARTBEAT_SECS", "10"))
IDLE_EXITS_HARD = int(os.environ.get("FB_IDLE_EXITS_HARD", "20"))

H = {"Authorization": f"Bearer {TOKEN}"}
_stop = threading.Event()
_current_shard = {"id": None}


def post(path, body, tries=6):
    """The control plane is the only thing that matters; retry hard."""
    for i in range(tries):
        try:
            r = requests.post(URL + path, json=body, headers=H, timeout=20)
            if r.status_code < 500:
                return r.json()
        except Exception:
            pass
        time.sleep(min(2 ** i, 20) * (0.7 + 0.6 * random.random()))
    return {}


def heartbeat_loop():
    while not _stop.is_set():
        out = post("/w/heartbeat", {"worker_id": WORKER_ID,
                                    "shard_id": _current_shard["id"]}, tries=3)
        if out.get("stop"):
            _stop.set()
        _stop.wait(HEARTBEAT_SECS)


# ------------------------------------------------------------------ engines

class EchoEngine:
    """Stand-in with a plausible cost shape: it takes real time per request so
    the deadline controller has something to control."""
    def __init__(self, model):
        self.model = model
        self.per_req = float(os.environ.get("FB_ECHO_SECS", "0.05"))

    def generate(self, prompts):
        time.sleep(self.per_req * len(prompts))
        out = []
        for p in prompts:
            # deterministic pseudo-classification so agreement is measurable
            h = sum(ord(ch) for ch in p) % 3
            out.append(["positive", "negative", "neutral"][h])
        return out


class VLLMEngine:
    def __init__(self, model):
        from vllm import LLM, SamplingParams
        self.SamplingParams = SamplingParams
        self.llm = LLM(
            model=model,
            gpu_memory_utilization=float(os.environ.get("FB_GPU_UTIL", "0.90")),
            max_model_len=int(os.environ.get("FB_MAX_LEN", "4096")),
            quantization=os.environ.get("FB_QUANT") or None,
            enforce_eager=os.environ.get("FB_EAGER", "0") == "1",
        )

    def generate(self, prompts):
        sp = self.SamplingParams(
            temperature=float(os.environ.get("FB_TEMP", "0")),
            max_tokens=int(os.environ.get("FB_MAX_TOKENS", "16")),
            seed=int(os.environ.get("FB_SEED", "0")),
        )
        outs = self.llm.generate(prompts, sp)
        return [o.outputs[0].text.strip() for o in outs]


def build_engine(model):
    return VLLMEngine(model) if ENGINE == "vllm" else EchoEngine(model)


# ------------------------------------------------------------------ accept

def make_acceptor(spec):
    """The customer's acceptance test, applied here so that only interchangeable
    output is ever counted or billed."""
    kind = (spec or {}).get("type", "any")
    if kind == "labels":
        allowed = {s.lower() for s in spec.get("labels", [])}
        return lambda o: o.strip().strip(".").lower() in allowed
    if kind == "json_keys":
        keys = spec.get("keys", [])
        def f(o):
            try:
                d = json.loads(o)
            except Exception:
                return False
            return all(k in d for k in keys)
        return f
    if kind == "nonempty":
        return lambda o: bool(o.strip())
    return lambda o: True


# ------------------------------------------------------------------ main

def main():
    print(f"[fb] worker {WORKER_ID} job {JOB} engine {ENGINE} model {MODEL}", flush=True)
    post("/w/register", {"worker_id": WORKER_ID, "job_id": JOB, "provider": PROVIDER,
                         "instance_id": os.environ.get("FB_INSTANCE_ID"),
                         "instance_type": ITYPE, "price_hr": PRICE_HR})
    threading.Thread(target=heartbeat_loop, daemon=True).start()

    engine = None
    idle = 0

    while not _stop.is_set():
        got = post("/w/claim", {"worker_id": WORKER_ID, "job_id": JOB})
        if got.get("stop"):
            print("[fb] job no longer running; exiting", flush=True)
            break
        shard = got.get("shard")
        if not shard:
            outstanding = got.get("outstanding", 0)
            if outstanding == 0:
                print("[fb] job fully claimed and done; exiting", flush=True)
                break
            idle += 1
            if idle >= IDLE_EXITS_HARD:
                print(f"[fb] idle too long with {outstanding} shard(s) outstanding; "
                      "exiting to stop burning the hour", flush=True)
                break
            # Stay: those shards are leased to machines that may already be gone.
            _stop.wait(min(5 * idle, 15))
            continue
        idle = 0

        if engine is None:                                  # pay model-load once
            t0 = time.time()
            engine = build_engine(got.get("model") or MODEL)
            print(f"[fb] engine ready in {time.time()-t0:.1f}s", flush=True)

        accept = make_acceptor(json.loads(got.get("accept") or "{}"))
        sid = shard["shard_id"]
        _current_shard["id"] = sid
        reqs = shard["requests"]
        print(f"[fb] shard {sid}: {len(reqs)} requests", flush=True)

        for i in range(0, len(reqs), CHUNK):
            if _stop.is_set():
                break
            batch = reqs[i : i + CHUNK]
            outs = engine.generate([r["prompt"] for r in batch])
            rows = [{"request_id": r["request_id"], "output": o, "accepted": accept(o)}
                    for r, o in zip(batch, outs)]
            # Post as we go. Anything already here survives a kill one line later.
            post("/w/results", {"worker_id": WORKER_ID, "job_id": JOB,
                                "shard_id": sid, "results": rows, "done": False})

        if not _stop.is_set():
            post("/w/results", {"worker_id": WORKER_ID, "job_id": JOB,
                                "shard_id": sid, "results": [], "done": True})
        _current_shard["id"] = None

    _stop.set()
    print("[fb] done", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
