---
name: record-evidence
description: Capture a command's real output as an immutable evidence artifact under docs/evidence/<phase>/ with the repository's standard provenance header. Use whenever a claim needs to become VERIFIED, or when asked to record, capture, or save evidence of a run.
---

# Record evidence

An evidence artifact is the record of a run that actually happened. It is what turns a
claim from "expected" into VERIFIED. Documentation, comments, and reasoning are not
evidence.

## The rule this skill exists to serve

No new behaviour may be labelled VERIFIED unless you either (a) ran it and saved
reproducible output here, or (b) cite an existing artifact. Evidence captured at an older
commit is HISTORICAL unless you confirm the relevant code is unchanged since.

## Artifacts are immutable

A wrong artifact is corrected by capturing a new one and explaining the correction in
`docs/STATE.md` — never by rewriting the old record. That is the rule.

The shared policy engine (`.agents/policy/guard.py`) blocks the ordinary ways of reaching
an existing artifact, for both Claude and Codex: the file tools, shell redirection, `rm`,
`mv`, `cp`, `ln`, `install`, `rsync`, `gzip`/`xz`, `sed -i`, and a recursive delete of any
directory containing the tree. It is a guardrail against an accident, not a boundary — an
interpreter or a constructed shell command can still reach one. The rule above binds
whether or not the hook catches a given spelling.

## Naming

```
docs/evidence/<phase>/<subject>-<aspect>.<ext>
```

`<phase>` matches the milestone the run belongs to (`v0` for the existing prototype).
Follow the established names: `local-demo-001-report.txt`, `local-demo-001-environment.txt`,
`local-demo-001-reconciliation.json`. Never reuse a name that exists.

## Header

Every text artifact opens with this provenance block. It is the standard for everything
captured from R0 onward:

```
captured_at=<ISO-8601 with offset>
database=<absolute path to the DB used, or "none">
python=<python3 --version output>
commit=<full git SHA at capture time>
<uname -a>
```

Generate it, do not hand-write it:

```bash
{
  echo "captured_at=$(date -Iseconds)"
  echo "database=${FB_DB:-none}"
  echo "python=$(python3 --version)"
  echo "commit=$(git rev-parse HEAD)"
  uname -a
} > docs/evidence/<phase>/<name>.txt
```

Then append the real command output beneath it. JSON artifacts carry the same five fields
as top-level keys alongside their data.

**The existing v0 artifacts do not meet this standard.** Five of the six files under
`docs/evidence/v0/` carry no header at all — only `local-demo-001-environment.txt` does,
and `local-demo-001-reconciliation.json` has none of the fields as keys. They predate the
standard. Cite them as HISTORICAL, do not treat them as the template, and do not rewrite
them to add a header: back-filling provenance onto a run you did not observe is fabrication,
and the artifacts are immutable for exactly that reason.

## Procedure

1. Confirm the target path does not exist. If it does, choose a new name.
2. Confirm the working tree state you are capturing — a dirty tree means the `commit=`
   line does not fully describe what ran. Say so in the artifact if so.
3. Run the command and capture its real output. Never paste expected or reconstructed output.
4. Write header + output to the new file.
5. Report the artifact path and what it does and does not prove.

## What it does not prove

Be explicit in your summary. A passing local chaos run is diagnostic evidence about v0's
durability under process kill. It is not evidence of request-level accounting correctness,
provider behaviour, cost, or pilot readiness — and roadmap Milestone 1 requires that no v0
result be presented as pilot-ready customer proof.
