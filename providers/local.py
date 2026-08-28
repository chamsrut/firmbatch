"""Local provider: workers are subprocesses on this machine.

Exists so the whole system -- leases, reaping, partial results, the deadline
controller, chaos kills -- can be exercised end to end before a single euro is
spent on a GPU. The Verda adapter below it is then the only untested surface.
"""

import os
import signal
import subprocess
import sys
import uuid

from .base import Launched, Provider

# Pretend price so the ledger produces a real cost-per-accepted-output number.
FAKE_PRICE_HR = float(os.environ.get("FB_LOCAL_PRICE_HR", "0.16"))


class LocalProvider(Provider):
    name = "local"

    def __init__(self, ctl_url, token, engine="echo", model="echo-model"):
        self.ctl_url, self.token, self.engine, self.model = ctl_url, token, engine, model
        self.procs: dict[str, subprocess.Popen] = {}

    def launch(self, job_id):
        worker_id = "w-" + uuid.uuid4().hex[:8]
        env = dict(os.environ)
        env.update({
            "FB_URL": self.ctl_url, "FB_TOKEN": self.token, "FB_JOB": job_id,
            "FB_WORKER_ID": worker_id, "FB_ENGINE": self.engine, "FB_MODEL": self.model,
            "FB_PROVIDER": "local", "FB_PRICE_HR": str(FAKE_PRICE_HR),
            "FB_INSTANCE_TYPE": "local-cpu", "PYTHONPATH": os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        })
        p = subprocess.Popen(
            [sys.executable, "-m", "firmbatch.worker.agent"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        self.procs[worker_id] = p
        return Launched(worker_id, str(p.pid), "local-cpu", FAKE_PRICE_HR)

    def kill(self, worker_id, instance_id):
        """SIGKILL, deliberately. A preempted machine gets no chance to tidy up
        and neither does this -- that is the failure mode we must survive."""
        p = self.procs.pop(worker_id, None)
        if p and p.poll() is None:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except Exception:
                p.kill()
        elif instance_id:
            try:
                os.kill(int(instance_id), signal.SIGKILL)
            except Exception:
                pass
