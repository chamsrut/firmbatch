from dataclasses import dataclass


@dataclass
class Launched:
    worker_id: str
    instance_id: str | None
    instance_type: str
    price_hr: float


class Provider:
    name = "base"

    def prepare(self, job_id: str, ctl_url: str, token: str) -> None:
        """One-off per-job setup (e.g. upload a startup script)."""

    def launch(self, job_id: str) -> Launched:
        raise NotImplementedError

    def kill(self, worker_id: str, instance_id: str | None) -> None:
        raise NotImplementedError

    def capacity_available(self) -> bool:
        return True
