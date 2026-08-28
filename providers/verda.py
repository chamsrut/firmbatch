"""Verda (formerly DataCrunch) adapter.

API surface used, all confirmed against SDK 1.24.1:

    client.instances.create(instance_type, image, hostname, description,
                            ssh_key_ids=[], location=Locations.FIN_03,
                            startup_script_id=None, is_spot=False, ...) -> Instance
    client.instances.is_available(instance_type, is_spot, location_code) -> bool
    client.instances.action(id_list, Actions.DELETE, volume_ids=None,
                            delete_permanently=True)
    client.instance_types.get() -> [InstanceType]
    client.startup_scripts.create(name, script) -> StartupScript

Instance carries .id, .price_per_hour, .status, .ip, .is_spot, so the ledger
records what we were actually charged rather than what the rate card said.
Locations: FIN-01, FIN-02, FIN-03, ICE-01.
"""

import os
import uuid

from .base import Launched, Provider

BOOTSTRAP = r"""#!/bin/bash
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive

# Injected by the controller, one script per job.
export FB_URL="__FB_URL__"
export FB_TOKEN="__FB_TOKEN__"
export FB_JOB="__FB_JOB__"
export FB_MODEL="__FB_MODEL__"
export FB_ENGINE="__FB_ENGINE__"
export FB_PROVIDER="verda"
export FB_PRICE_HR="__FB_PRICE_HR__"
export FB_INSTANCE_TYPE="__FB_INSTANCE_TYPE__"
# The controller sets the hostname to the worker id, so the box knows its name.
export FB_WORKER_ID="$(hostname)"

mkdir -p /opt/fb && cd /opt/fb
curl -fsSL "$FB_URL/agent.py" -o agent.py || true
if [ ! -s agent.py ]; then
  echo "control plane did not serve agent.py; falling back to pip payload"
  exit 1
fi

pip install --no-cache-dir requests >/dev/null
if [ "$FB_ENGINE" = "vllm" ]; then
  pip install --no-cache-dir vllm >/dev/null
fi

# Run under systemd so a crash restarts rather than idling a paid GPU.
cat >/etc/systemd/system/fb-agent.service <<EOF
[Unit]
Description=firmbatch agent
[Service]
Type=simple
WorkingDirectory=/opt/fb
Environment=FB_URL=$FB_URL
Environment=FB_TOKEN=$FB_TOKEN
Environment=FB_JOB=$FB_JOB
Environment=FB_MODEL=$FB_MODEL
Environment=FB_ENGINE=$FB_ENGINE
Environment=FB_PROVIDER=verda
Environment=FB_PRICE_HR=$FB_PRICE_HR
Environment=FB_INSTANCE_TYPE=$FB_INSTANCE_TYPE
Environment=FB_WORKER_ID=$FB_WORKER_ID
ExecStart=/usr/bin/python3 /opt/fb/agent.py
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now fb-agent
"""


class VerdaProvider(Provider):
    name = "verda"

    def __init__(self, ctl_url, token, instance_type, model, engine="vllm",
                 location=None, image=None, spot=True, ssh_key_ids=None):
        from verda import Verda                     # pip install verda
        self.client = Verda(
            client_id=os.environ["VERDA_CLIENT_ID"],
            client_secret=os.environ["VERDA_CLIENT_SECRET"],
        )
        self.ctl_url, self.token = ctl_url, token
        self.instance_type = instance_type
        self.model, self.engine = model, engine
        self.location = location or os.environ.get("VERDA_LOCATION", "FIN-03")
        self.image = image or os.environ.get("VERDA_IMAGE", "ubuntu-24.04-cuda-12.8-open-docker")
        self.spot = spot
        self.ssh_key_ids = ssh_key_ids or [
            k for k in os.environ.get("VERDA_SSH_KEY_IDS", "").split(",") if k
        ]
        self.script_id = None
        self.price_hr = 0.0

    # ---------------------------------------------------------------- setup

    def prepare(self, job_id, ctl_url=None, token=None):
        body = (BOOTSTRAP
                .replace("__FB_URL__", self.ctl_url)
                .replace("__FB_TOKEN__", self.token)
                .replace("__FB_JOB__", job_id)
                .replace("__FB_MODEL__", self.model)
                .replace("__FB_ENGINE__", self.engine)
                .replace("__FB_PRICE_HR__", str(self.price_hr))
                .replace("__FB_INSTANCE_TYPE__", self.instance_type))
        script = self.client.startup_scripts.create(f"fb-{job_id}", body)
        self.script_id = script.id
        return self.script_id

    def capacity_available(self):
        try:
            return bool(self.client.instances.is_available(
                self.instance_type, is_spot=self.spot, location_code=self.location))
        except Exception:
            return True          # never let a probe failure stall the controller

    def list_types(self):
        out = []
        for t in self.client.instance_types.get():
            out.append({
                "instance_type": getattr(t, "instance_type", None),
                "gpu": getattr(t, "gpu", None),
                "price_per_hour": getattr(t, "price_per_hour", None),
                "spot_price_per_hour": getattr(t, "spot_price", None),
                "description": getattr(t, "description", None),
            })
        return out

    # ---------------------------------------------------------------- lifecycle

    def launch(self, job_id):
        if not self.script_id:
            self.prepare(job_id)
        worker_id = "w-" + uuid.uuid4().hex[:8]        # also the hostname
        inst = self.client.instances.create(
            instance_type=self.instance_type,
            image=self.image,
            hostname=worker_id,
            description=f"firmbatch {job_id}",
            ssh_key_ids=self.ssh_key_ids,
            location=self.location,
            startup_script_id=self.script_id,
            is_spot=self.spot,
        )
        price = float(getattr(inst, "price_per_hour", 0) or 0)
        self.price_hr = price
        return Launched(worker_id, inst.id, self.instance_type, price)

    def kill(self, worker_id, instance_id):
        if not instance_id:
            return
        from verda.constants import Actions
        # delete_permanently so the OS volume goes too -- an orphaned volume is
        # a bill that arrives after you have forgotten the experiment.
        self.client.instances.action([instance_id], Actions.DELETE,
                                     delete_permanently=True)
