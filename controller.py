"""The deadline controller.

Greedy on purpose. It measures the realised acceptance rate, projects a finish
time, and buys or releases machines to close the gap. There is no bin packing
and no optimiser: a greedy loop with a time buffer hits deadlines, and an
optimiser does not exist by week four.
"""

import math
import os
import time

from .control import db

TICK          = float(os.environ.get("FB_TICK", "15"))
BUFFER_FRAC   = float(os.environ.get("FB_BUFFER_FRAC", "0.20"))   # keep 20% of the window spare
WORKER_STALE  = float(os.environ.get("FB_WORKER_STALE", "75"))    # no heartbeat -> presumed preempted
LAUNCH_PER_TICK = int(os.environ.get("FB_LAUNCH_PER_TICK", "2"))


def _fmt(s):
    if s is None:
        return "  ?  "
    m, sec = divmod(int(max(0, s)), 60)
    return f"{m:02d}:{sec:02d}"


def run(job_id, provider, max_workers=4, min_workers=1, firm_switch=True, quiet=False):
    job = db.get_job(job_id)
    if not job:
        raise SystemExit(f"no such job {job_id}")
    provider.prepare(job_id, None, None)
    window = max(1.0, job["deadline_ts"] - time.time())
    launched_total = 0

    try:
        while True:
            db.reap()
            st = db.status(job_id)

            # --- retire workers that stopped heartbeating (preemption, crash, OOM)
            now = time.time()
            for w in db.live_workers(job_id):
                if w["last_seen_ts"] and now - w["last_seen_ts"] > WORKER_STALE:
                    db.kill_worker(w["id"], "no_heartbeat")
                    try:
                        provider.kill(w["id"], w["instance_id"])
                    except Exception as e:
                        print("  ! kill failed:", e)

            if st["status"] != "running" or st["remaining"] == 0:
                break

            live = db.live_workers(job_id)
            n_live = len(live)
            time_left = job["deadline_ts"] - now
            usable = max(1.0, time_left - BUFFER_FRAC * window)
            need_rate = st["remaining"] / usable                       # req/s we must sustain

            if st["rate_per_s"] > 0 and n_live > 0:
                per_worker = st["rate_per_s"] / n_live
                want = math.ceil(need_rate / per_worker) if per_worker > 0 else n_live + 1
            else:
                want = max(min_workers, n_live)                        # nothing measured yet

            want = max(min_workers, min(max_workers, want))

            # --- endgame: stop betting on capacity that can be taken away
            if firm_switch and time_left < BUFFER_FRAC * window and hasattr(provider, "spot"):
                if provider.spot:
                    provider.spot = False
                    print("  * endgame: switching new workers to non-preemptible")

            if want > n_live and provider.capacity_available():
                for _ in range(min(want - n_live, LAUNCH_PER_TICK)):
                    try:
                        h = provider.launch(job_id)
                        db.register_worker(h.worker_id, job_id, provider.name,
                                           h.instance_id, h.instance_type, h.price_hr)
                        launched_total += 1
                    except Exception as e:
                        print("  ! launch failed:", e)
                        break
            elif want < n_live:
                # Release idle machines first, then the most recently started:
                # newest has the least sunk model-load cost, and an idle worker
                # has no in-flight shard to hand back.
                order = sorted(
                    live,
                    key=lambda x: (db.worker_has_lease(x["id"]), -x["started_ts"]),
                )
                for w in order[: n_live - want]:
                    db.kill_worker(w["id"], "scaled_down")
                    try:
                        provider.kill(w["id"], w["instance_id"])
                    except Exception as e:
                        print("  ! kill failed:", e)

            if not quiet:
                flag = "ON TRACK" if st["on_track"] else "BEHIND  "
                print(f"[{time.strftime('%H:%M:%S')}] {flag} "
                      f"{st['completed']}/{st['n_requests']} done "
                      f"({st['accepted']} accepted) | shards p{st['shards']['pending']}"
                      f"/l{st['shards']['leased']}/d{st['shards']['done']} | "
                      f"{st['rate_per_s']:.2f}/s | eta {_fmt(st['eta_s'])} | "
                      f"deadline in {_fmt(st['seconds_to_deadline'])} | "
                      f"workers {n_live}->{want}", flush=True)

            time.sleep(TICK)
    finally:
        for w in db.live_workers(job_id):
            db.kill_worker(w["id"], "job_complete")
            try:
                provider.kill(w["id"], w["instance_id"])
            except Exception:
                pass

    st = db.status(job_id)
    late = st["seconds_to_deadline"] < 0
    print(f"\n  job {job_id}: {st['completed']}/{st['n_requests']} complete, "
          f"{st['accepted']} accepted, {launched_total} workers used, "
          f"{'MISSED' if late else 'met'} the deadline "
          f"({'+' if late else ''}{-st['seconds_to_deadline']}s)")
    return st
