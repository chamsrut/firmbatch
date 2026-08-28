---
name: verify
description: Run the Firmbatch verification pass — one script covering layout, agent configuration, repository hygiene, property tests, ruff, and the agent policy tests. Use before claiming any change is complete, and whenever asked to verify, check, or validate the repository. The destructive chaos experiment is opt-in via --chaos and is never part of the default pass.
---

# Firmbatch verification

Two distinct things live here. Do not merge them.

- **The default pass** is fast, deterministic, and side-effect free. It touches no
  database and writes no evidence artifact. Run it before reporting any change complete.
- **`--chaos`** is an integration *experiment*, not verification. It hard-kills
  workers mid-job and takes minutes. Run it only when explicitly asked.

## Default pass

One command. Run it from anywhere — the script resolves its own repository root and
runs each gate from the directory that gate needs.

```bash
./scripts/verify-repository.sh
```

That script is the single entry point: the human, this skill, and
`.github/workflows/ci.yml` all invoke the same file, so all three are provably running
the same gates. **Do not run the underlying commands individually** — a gate that only
exists in someone's memory of the right command line is a gate that stops being true.
If a check is missing, add it to the script.

It prints PASS or FAIL per gate, runs every gate even after one fails, and exits
non-zero if any failed. Currently twelve gates, in four groups:

| Group | Gates |
| --- | --- |
| layout | directory named `firmbatch`; required R0 files present; the three `.claude/skills` symlinks resolve into `.agents/skills` |
| agent configuration | JSON parses; TOML parses and declares `read_only`; the Claude hook covers the right tools and invokes the shared guard; Claude reviewers grant only read-only tools; Codex reviewers declare `read_only` and grant no write tool |
| repository hygiene | no credential file, private key, or SQLite database is tracked by git |
| functional | property tests (from the parent directory), `ruff check`, agent policy tests |

Report each gate as PASS or FAIL with the failing names. All must pass.

### Rules for this pass

- **Never run `ruff check --fix` or `ruff format`.** v0's terse style is deliberate and
  is on its way out under the v1 roadmap. A lint finding in untouched v0 code is
  reported to the human, never auto-rewritten.
- Ruff applies to code **you** wrote or modified. If it flags pre-existing v0 code you
  did not touch, say so explicitly and separate those findings from yours.
- A failing gate is a result, not an obstacle. Report it; do not weaken the rule,
  add an ignore, or narrow the scope to make it pass.

## `--chaos` (explicit only)

The destructive local baseline. It must never overwrite an existing database, reuse an
existing evidence artifact, or collide with a control plane that is already running.

**Isolate the port, not only the database.** `fb serve` defaults to `0.0.0.0:8080` and
`fb demo` defaults to `127.0.0.1:8080`. If any control plane is already on 8080, the new
`serve` fails to bind, the backgrounded job dies unnoticed, and every worker registers
against the **other** database — writing into a store this run was supposed to leave
alone, and ending `0/4000` with the deadline missed. That failure looks exactly like v0
failing its durability baseline, and it is not.

```bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/.."

# A fresh database and a free loopback port, chosen together.
export FB_DB="$(mktemp -d)/chaos-$(date +%s).db"

# ALWAYS set this before `serve`: fb.py prints $FB_TOKEN on stdout at startup, and this
# procedure tells you to capture stdout. Without the export, a real token lands in an
# immutable artifact.
export FB_TOKEN=dev-token

# Pin the knobs that decide the behaviour under test. All are read from the ambient
# shell, none appear in the provenance header, and a leftover export silently makes one
# baseline incomparable with the next.
export FB_LEASE_SECS=90 FB_WORKER_STALE=75 FB_TICK=15 FB_LAUNCH_PER_TICK=2
export FB_CHUNK=25 FB_HEARTBEAT_SECS=10 FB_ECHO_SECS=0.05

# Isolate the demo input file too: fb.py hard-codes /tmp/fb_demo.jsonl (defect D8), so
# two concurrent runs corrupt each other's job regardless of FB_DB and the port.
export TMPDIR="$(mktemp -d)"
PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"

# Bind loopback only: the operator API has no auth beyond FB_TOKEN.
python3 -m firmbatch.fb serve --host 127.0.0.1 --port "$PORT" &
SERVE_PID=$!
trap 'kill "$SERVE_PID" 2>/dev/null || true' EXIT INT TERM

# Wait for readiness, and fail loudly if it never binds.
for _ in $(seq 1 50); do
  if curl -sf "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then READY=1; break; fi
  if ! kill -0 "$SERVE_PID" 2>/dev/null; then echo "serve died; port $PORT busy?" >&2; exit 1; fi
  sleep 0.2
done
[ "${READY:-}" = 1 ] || { echo "control plane never became ready on $PORT" >&2; exit 1; }

# --port is what makes the workers talk to THIS control plane.
# --chaos-after must clear the controller's scale-down window, or the shards come back
# through the ORDINARY release path and the run evidences nothing about preemption --
# which is exactly how the v0 baseline came to claim a SIGKILL it could not show.
# --deadline must then leave room for FB_WORKER_STALE (75s) detection after the kill.
python3 -m firmbatch.fb demo --n 4000 --deadline +6m --chaos-n 3 --chaos-after 60 --port "$PORT"
```

Before starting:

1. Never point `FB_DB` at `.data/` or at any path referenced by a file under
   `docs/evidence/`. The `mktemp -d` above already guarantees a new path — do not
   replace it with a fixed name.
2. The `trap` is the cleanup. Do not rely on remembering to kill the server.
3. Record the pinned `FB_*` values in the artifact alongside the standard header. The
   header does not carry them, and without them the run is not reproducible.
4. Assert afterwards that `no_heartbeat` appears in the report's stop-reason column. If
   every worker reads `scaled_down` or `job_complete`, the kill did not drive the
   recovery and the run does not evidence the preemption path.

### What the console output is for

The kill itself is only ever visible on **stdout**: `fb chaos` deliberately writes no
kill record to the database (`fb.py`), so a worker killed mid-flight is distinguishable
from one scaled down only by the `>>> CHAOS: killing N workers mid-job <<<` line and by a
`no_heartbeat` stop reason appearing afterwards. **Capture stdout**, or the run cannot
evidence what it was run to evidence. This is exactly how the v0 baseline came to claim
a SIGKILL it could not show.

The run produces console output only. It becomes evidence **only** if the human asks for
it — that is a separate `/record-evidence` call, and the guard blocks any attempt to
write over an existing artifact.

## Reporting

Close with the roadmap §7 shape:

- files changed;
- tests and results (each gate, plus chaos if run);
- remaining risks;
- whether the acceptance criteria are met;
- what remains.

State plainly whether anything is being claimed as VERIFIED, and on what captured evidence.
