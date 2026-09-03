---
name: verify
description: Run the Firmbatch verification pass — one script covering layout, agent configuration, repository hygiene, v0 property tests, ruff, the agent policy tests, and the v1 PostgreSQL foundation suite. It needs a real PostgreSQL 16 server and creates and drops a disposable database and roles. Use before claiming any change is complete, and whenever asked to verify, check, or validate the repository. The destructive chaos experiment is opt-in via --chaos and is never part of the default pass.
---

# Firmbatch verification

Two distinct things live here. Do not merge them.

- **The default pass** is fast, deterministic, and writes no evidence artifact. Run it
  before reporting any change complete. Since Milestone 2.1 it is **not side-effect
  free**: its last gate runs the v1 foundation suite against a real PostgreSQL 16 server,
  where it creates and then drops a disposable database and three throwaway login roles.
  See the prerequisites below.
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
non-zero if any failed. Currently **fourteen** gates, in four groups:

| Group | Gates |
| --- | --- |
| layout | directory named `firmbatch`; all required repository files present (R0 tooling plus the v1 control-plane foundation); the three `.claude/skills` symlinks resolve into `.agents/skills` |
| agent configuration | JSON parses; TOML parses and declares the read-only sandbox; the Claude hook covers the right tools and invokes the shared guard; Claude reviewers grant only read-only tools; Codex reviewers declare the read-only sandbox schema |
| repository hygiene | no credential file, private key, or SQLite database is tracked by git |
| functional | v0 property tests (from the parent directory), `ruff check`, agent policy tests, the runtime import closure check, **the v1 PostgreSQL foundation suite** |

Report each gate as PASS or FAIL with the failing names. All must pass.

### The runtime import closure gate

`scripts/check-runtime-imports.py --static` checks that every third-party import made by
production code under `control_plane/` (the test package excluded) is provided by a
distribution pinned in `requirements-v1-lock.txt`. The development lock is a superset, so
without this a production module could import `pytest`, install cleanly, pass the whole
suite, and fail on first use in production.

CI runs the same script with `--dynamic` inside a clean virtual environment built from the
runtime lock alone: it imports every production module, runs a real entry point
(`migrate heads`), and asserts nothing was served out of another environment's
site-packages. That half catches deferred and conditional imports, which no parser sees.

### Prerequisites for the PostgreSQL gate

The foundation suite tests PostgreSQL semantics -- forced row-level security, role
attributes, referential integrity, transaction-local settings. None of that has a
faithful in-memory substitute, so there is no fake and no fallback. **The gate fails when
the server is absent; it never skips.** A skipped isolation suite reports the same green
as a passing one.

Two things must be true:

1. **`FIRMBATCH_TEST_DATABASE_URL`** points at a *maintenance* database (`postgres` or
   `template1`) on a PostgreSQL **16** server. The suite refuses any other major version.
   Local WSL uses native PostgreSQL, not Docker:

   ```bash
   export FIRMBATCH_TEST_DATABASE_URL='postgresql+psycopg://USER@/postgres?host=/var/run/postgresql&port=5432'
   ```

   **Every field must be explicit** -- user, host, port, database -- and there may be
   exactly one of each. libpq fills whatever a URL omits from `PGUSER`, `PGHOST`, `PGPORT`
   and `PGDATABASE`, so an omitted field means the ambient environment decides where the
   connection goes; a multi-host failover list means libpq decides at connect time. Both
   are refused. If a URL that used to work now fails, it is almost certainly the port.

   The admin role needs `CREATEDB` and `CREATEROLE`, and needs neither `SUPERUSER` nor
   `BYPASSRLS`.

2. **The server is attested as a disposable test cluster.** Every PostgreSQL cluster has a
   `postgres` database, production included, so the URL alone is not evidence that
   anything may be created or dropped there. The helpers require a marker somebody created
   on purpose -- once per cluster:

   ```bash
   cd "$(git rev-parse --show-toplevel)/.."
   FIRMBATCH_ENV=test python3 -m firmbatch.control_plane.testing.attestation --mark
   ```

   (`--check` reports without changing anything; `--unmark` withdraws it.) CI marks its
   own ephemeral `postgres:16` service container in an explicit step, which satisfies the
   check rather than weakening it.

**Never mark a server that holds anything you would miss.** The marker is the last thing
standing between a mistyped environment variable and a `DROP DATABASE`.

### What the gate does to the database

It creates `firmbatch_test_<12 random hex>` plus **three** throwaway login roles -- a
per-run owner (which is the migration principal and the deletion authority), an
application role and a provisioning role -- migrates the database, runs the suite, and
removes all four.

The final `DROP DATABASE` is issued **as the per-run owner**, not with admin authority, so
PostgreSQL's ownership check applies to whatever object is present at that instant: a
same-name replacement owned by anybody else survives. Roles are removed by
rename-verify-drop inside one transaction, for the same reason.

The helpers also refuse any database whose name does not match the disposable pattern,
refuse to run unless `FIRMBATCH_ENV=test`, and re-check the attestation, the cluster
identity and each object's recorded OID and provenance marker immediately before dropping.
If the suite is interrupted, a `firmbatch_test_*` database may survive; it is safe to drop
by hand (as its owner role, or as a superuser).

**The threat boundary.** These measures stop the realistic failures: a concurrent test
process, a stale handle, a same-name replacement, a mistyped variable, and any
non-superuser administrator. They do **not** stop a concurrent *superuser*, who can drop
and recreate anything under any owner at any moment; PostgreSQL offers no lock that would.
That residual is documented in ADR 0004 rather than papered over.

Dependencies come from the hash-pinned lock, not from the direct pins:

```bash
python3 -m pip install --require-hashes -r requirements-v1-dev-lock.txt
```

### Rules for this pass

- **Never run `ruff check --fix` or `ruff format`.** v0's terse style is deliberate and
  is on its way out under the v1 roadmap. A lint finding in untouched v0 code is
  reported to the human, never auto-rewritten.
- Ruff applies to code **you** wrote or modified. If it flags pre-existing v0 code you
  did not touch, say so explicitly and separate those findings from yours.
- A failing gate is a result, not an obstacle. Report it; do not weaken the rule,
  add an ignore, or narrow the scope to make it pass.
- **Never satisfy the PostgreSQL gate by relaxing it.** Marking a real cluster as
  disposable, pointing the URL at something that matters, or making the suite skip when
  the server is missing all turn a failing gate green without making the claim true.
  If the server is unavailable, say so and stop.
- On failure the gate prints **two** windows and names a retained log file: the
  heading and opening frames (which test, in what context) and the tail of the log (the
  terminal exception, which is what actually explains it). A pytest failure puts the
  actionable `OperationalError` or `InsufficientPrivilege` at the *end*, behind however
  many wrapper frames the call took, so a window at the top alone shows nothing useful.
  The reporter uses no pipes: `awk | head` under `set -o pipefail` exits 141 on SIGPIPE and
  takes the whole script with it, which is how a real failure once vanished entirely.

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
