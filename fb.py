#!/usr/bin/env python3
"""fb -- the operator CLI.

  fb serve                                 run the control plane
  fb submit  --file demo.jsonl --deadline +20m
  fb run     --provider local|verda --max-workers 4
  fb watch                                 live status
  fb chaos   [--n 1]                       hard-kill live workers mid-job
  fb report                                realised cost per accepted output
  fb probe                                 verda: instance types, spot, prices

Every command defaults to the most recent job, so a demo is four words long.
"""

import argparse
import json
import os
import random
import re
import sys
import time

from .control import db


def parse_deadline(s):
    m = re.fullmatch(r"\+(\d+)([smh])", s.strip())
    if m:
        n, unit = int(m.group(1)), m.group(2)
        return time.time() + n * {"s": 1, "m": 60, "h": 3600}[unit]
    return float(s)


def resolve(job_id):
    j = job_id or db.latest_job()
    if not j:
        raise SystemExit("no jobs yet -- run `fb submit` first")
    return j


# ------------------------------------------------------------------ commands

def cmd_serve(a):
    import uvicorn
    db.init()
    print(f"control plane on http://{a.host}:{a.port}  (token {os.environ.get('FB_TOKEN','dev-token')})")
    uvicorn.run("firmbatch.control.app:app", host=a.host, port=a.port, log_level="warning")


def cmd_submit(a):
    db.init()
    reqs = [json.loads(l) for l in open(a.file) if l.strip()]
    for i, r in enumerate(reqs):
        r.setdefault("request_id", f"r{i:06d}")
    accept = json.loads(a.accept) if a.accept else {"type": "nonempty"}
    job_id = db.create_job(a.name, a.model, parse_deadline(a.deadline),
                           a.shard_size, reqs, accept)
    n_shards = -(-len(reqs) // a.shard_size)
    print(f"{job_id}  {len(reqs)} requests in {n_shards} shards, "
          f"deadline in {int(parse_deadline(a.deadline)-time.time())}s")
    return job_id


def cmd_run(a):
    from . import controller
    db.init()
    job_id = resolve(a.job)
    job = db.get_job(job_id)
    ctl = a.ctl_url or f"http://127.0.0.1:{a.port}"
    token = os.environ.get("FB_TOKEN", "dev-token")

    if a.provider == "local":
        from .providers.local import LocalProvider
        p = LocalProvider(ctl, token, engine=a.engine, model=job["model"])
    elif a.provider == "verda":
        from .providers.verda import VerdaProvider
        p = VerdaProvider(ctl, token, instance_type=a.instance_type,
                          model=job["model"], engine=a.engine,
                          location=a.location, spot=not a.on_demand)
    else:
        raise SystemExit("unknown provider")

    controller.run(job_id, p, max_workers=a.max_workers,
                   min_workers=a.min_workers, firm_switch=not a.no_firm_switch)


def cmd_watch(a):
    db.init()
    job_id = resolve(a.job)
    while True:
        st = db.status(job_id)
        if not st:
            raise SystemExit("gone")
        bar_w = 34
        f = 0 if not st["n_requests"] else st["completed"] / st["n_requests"]
        bar = "#" * int(f * bar_w) + "." * (bar_w - int(f * bar_w))
        sys.stdout.write(
            f"\r[{bar}] {st['completed']}/{st['n_requests']} "
            f"acc {st['accepted']} | {st['rate_per_s']:.2f}/s | "
            f"workers {st['workers_live']} | deadline {st['seconds_to_deadline']}s "
            f"| {'on track' if st['on_track'] else 'BEHIND'}   ")
        sys.stdout.flush()
        if st["status"] != "running" or st["remaining"] == 0:
            print()
            break
        time.sleep(2)
    for e in db.events(job_id, 12):
        print(f"  {time.strftime('%H:%M:%S', time.localtime(e['ts']))}  "
              f"{e['kind']:<16} {e['detail'] or ''}")


def cmd_chaos(a):
    """Hard-kill live workers. This is the demo: the job must not notice."""
    db.init()
    job_id = resolve(a.job)
    live = db.live_workers(job_id)
    if not live:
        print("no live workers")
        return
    victims = random.sample(live, min(a.n, len(live)))
    for w in victims:
        print(f"  killing {w['id']} ({w['instance_type']}, {w['provider']}) -- "
              "no notice, no cleanup, exactly like a preemption")
        # Deliberately NOT calling db.kill_worker: a machine that is taken away
        # does not get to update our database. The controller has to infer it
        # from the missing heartbeat, which is the path that must work in
        # production.
        if w["provider"] == "local":
            from .providers.local import LocalProvider
            LocalProvider("", "").kill(w["id"], w["instance_id"])
        elif w["provider"] == "verda":
            from .providers.verda import VerdaProvider
            os.environ.setdefault("VERDA_CLIENT_ID", "")
            VerdaProvider("", "", a.instance_type, "", spot=True).kill(w["id"], w["instance_id"])
    print(f"  killed {len(victims)}. Leases expire within "
          f"{os.environ.get('FB_LEASE_SECS','90')}s and the shards return to the pool.")


def cmd_report(a):
    db.init()
    job_id = resolve(a.job)
    st, led = db.status(job_id), db.ledger(job_id)
    print(f"\n  job     {job_id}  ({led['name']})")
    print(f"  status  {st['status']}   {st['completed']}/{st['n_requests']} complete, "
          f"{st['accepted']} accepted "
          f"({100*st['accepted']/max(1,st['completed']):.1f}% of completed)")
    print(f"  shards  done {st['shards']['done']}, "
          f"leased {st['shards']['leased']}, pending {st['shards']['pending']}")
    print(f"\n  {'worker':<12}{'type':<14}{'$/h':>7}{'wall h':>9}{'billed h':>10}"
          f"{'cost':>9}   reason")
    for w in led["workers"]:
        print(f"  {w['worker']:<12}{(w['instance_type'] or '-'):<14}{w['price_hr']:>7.3f}"
              f"{w['wall_h']:>9.3f}{w['billed_h']:>10.3f}{w['cost']:>9.3f}   {w['stop_reason']}")
    print(f"\n  total cost                 ${led['total_cost']:.4f}")
    if led["cost_per_1m_accepted"] is not None:
        print(f"  cost per 1k accepted       ${led['cost_per_1k_accepted']:.6f}")
        print(f"  COST PER 1M ACCEPTED       ${led['cost_per_1m_accepted']:.2f}   "
              f"<- the only number that goes in a quote\n")


def cmd_probe(a):
    from .providers.verda import VerdaProvider
    p = VerdaProvider("", "", a.instance_type or "", "", spot=True, location=a.location)
    print(f"  {'instance_type':<22}{'gpu':<26}{'$/h':>9}   spot avail")
    for t in p.list_types():
        it = t["instance_type"] or "?"
        avail = ""
        if a.check:
            try:
                avail = "yes" if p.client.instances.is_available(
                    it, is_spot=True, location_code=a.location) else "no"
            except Exception as e:
                avail = "err"
        print(f"  {it:<22}{str(t['gpu'])[:24]:<26}{str(t['price_per_hour']):>9}   {avail}")


def cmd_demo(a):
    """End-to-end local proof: submit, run, kill workers mid-flight, report."""
    import subprocess, threading
    db.init()
    here = os.path.dirname(os.path.abspath(__file__))
    subprocess.run([sys.executable, os.path.join(here, "demo", "make_requests.py"),
                    str(a.n), "/tmp/fb_demo.jsonl"], check=True)

    ns = argparse.Namespace(file="/tmp/fb_demo.jsonl", name="demo-classify",
                            model="echo-model", deadline=a.deadline,
                            shard_size=a.shard_size,
                            accept='{"type":"labels","labels":["positive","negative","neutral"]}')
    job_id = cmd_submit(ns)

    def chaos_later():
        time.sleep(a.chaos_after)
        print(f"\n  >>> CHAOS: killing {a.chaos_n} workers mid-job <<<")
        cmd_chaos(argparse.Namespace(job=job_id, n=a.chaos_n, instance_type=None))
    if a.chaos_n:
        threading.Thread(target=chaos_later, daemon=True).start()

    cmd_run(argparse.Namespace(job=job_id, provider="local", engine="echo",
                               ctl_url=a.ctl_url, port=a.port, max_workers=a.max_workers,
                               min_workers=1, instance_type=None, location=None,
                               on_demand=False, no_firm_switch=True))
    cmd_report(argparse.Namespace(job=job_id))


# ------------------------------------------------------------------ argparse

def main():
    ap = argparse.ArgumentParser(prog="fb")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve"); s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=8080); s.set_defaults(f=cmd_serve)

    s = sub.add_parser("submit")
    s.add_argument("--file", required=True); s.add_argument("--name", default="job")
    s.add_argument("--model", default="echo-model"); s.add_argument("--deadline", default="+20m")
    s.add_argument("--shard-size", type=int, default=200); s.add_argument("--accept", default=None)
    s.set_defaults(f=cmd_submit)

    s = sub.add_parser("run")
    s.add_argument("--job"); s.add_argument("--provider", default="local")
    s.add_argument("--engine", default="echo"); s.add_argument("--ctl-url")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--max-workers", type=int, default=4)
    s.add_argument("--min-workers", type=int, default=1)
    s.add_argument("--instance-type", default=os.environ.get("VERDA_INSTANCE_TYPE"))
    s.add_argument("--location", default=os.environ.get("VERDA_LOCATION", "FIN-03"))
    s.add_argument("--on-demand", action="store_true")
    s.add_argument("--no-firm-switch", action="store_true")
    s.set_defaults(f=cmd_run)

    s = sub.add_parser("watch"); s.add_argument("--job"); s.set_defaults(f=cmd_watch)

    s = sub.add_parser("chaos"); s.add_argument("--job"); s.add_argument("--n", type=int, default=1)
    s.add_argument("--instance-type", default=None); s.set_defaults(f=cmd_chaos)

    s = sub.add_parser("report"); s.add_argument("--job"); s.set_defaults(f=cmd_report)

    s = sub.add_parser("probe")
    s.add_argument("--location", default=os.environ.get("VERDA_LOCATION", "FIN-03"))
    s.add_argument("--instance-type", default=None)
    s.add_argument("--check", action="store_true", help="also query spot availability per type")
    s.set_defaults(f=cmd_probe)

    s = sub.add_parser("demo")
    s.add_argument("--n", type=int, default=2000); s.add_argument("--deadline", default="+4m")
    s.add_argument("--shard-size", type=int, default=100)
    s.add_argument("--max-workers", type=int, default=4)
    s.add_argument("--chaos-after", type=float, default=25)
    s.add_argument("--chaos-n", type=int, default=2)
    s.add_argument("--ctl-url"); s.add_argument("--port", type=int, default=8080)
    s.set_defaults(f=cmd_demo)

    a = ap.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
