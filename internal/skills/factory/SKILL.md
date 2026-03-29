---
name: factory
description: Agent-only FSM runbook for operating Hal safely from setup to merge.
user-invocable: false
---

# Hal Factory Operator — v2 (Agent-Only)

Operate Hal as a **deterministic finite-state machine**.
Use machine contracts (`--json`) for all decisions.

## Non-Negotiable Rules

1. Always run `hal doctor --json` and `hal status --json` before workflow actions.
2. If uncertain, run `hal continue --json` and execute `nextCommand`.
3. Never hand-edit `.hal/prd.json`, `.hal/auto-state.json`, or `.hal/progress.txt`.
4. Prefer non-deprecated flags/commands; use compatibility fallbacks only when needed.
5. After each major command, re-run `hal status --json`.

---

## 0) Capability Discovery (once per session)

Run:

```bash
hal --help
hal auto --help
hal convert --help
hal review --help
```

Set capability booleans:
- `HAS_CI`: `hal ci` command exists
- `HAS_AUTO_COMPOUND`: `hal auto --compound` exists
- `HAS_SKIP_CI`: `hal auto --skip-ci` exists
- `HAS_SKIP_PR`: `hal auto --skip-pr` exists
- `HAS_GRANULAR`: `hal convert --granular` exists

Derived compatibility values:
- `AUTO_SKIP_FLAG = --skip-ci | --skip-pr | ""`
- `COMPOUND_ENTRY_CMD`:
  - if `HAS_AUTO_COMPOUND`: `hal auto --compound` (optionally `--report <path>`)
  - else if legacy `--report` exists: `hal auto --report <path>`

---

## 1) Bootstrap Protocol (repo setup)

Run in order:

```bash
hal init
hal links refresh
hal doctor --json
```

If doctor indicates remediations:

```bash
hal repair --json
hal doctor --json
```

If blocking failures remain, stop and report blockers.

---

## 2) Deterministic Control Algorithm

Use this exact loop:

```text
LOOP
  A) doctor = hal doctor --json
     if doctor not healthy:
       run hal repair --json
       re-run doctor
       if still unhealthy: STOP with blockers

  B) status = hal status --json

  C) switch(status.state):
       not_initialized           -> run bootstrap protocol; continue
       hal_initialized_no_prd   -> run PRD-entry policy
       manual_in_progress       -> run "hal auto" (default) or "hal run" if user asked manual
       manual_complete          -> run ship policy
       compound_active          -> run "hal auto --resume"
       compound_complete        -> run "hal report"; if user requested next cycle run COMPOUND_ENTRY_CMD
       review_loop_complete     -> stop, propose: "hal plan" or review loop continuation
       default                  -> run "hal continue --json" and execute nextCommand

  D) After action, run hal status --json and summarize checkpoint
END
```

---

## 3) PRD-Entry Policy (`hal_initialized_no_prd`)

Branch logic:

1. If user supplied requirements text:
   ```bash
   hal plan "<feature>"
   ```
   Then:
   - prefer `hal auto` for autonomous execution,
   - else fallback manual: `hal convert && hal validate && hal run`.

2. If markdown PRD already exists:
   - prefer `hal auto [<markdown-path>]` when supported,
   - else fallback manual conversion path.

3. If no requirements and no markdown PRD:
   - stop and ask user for requirements.

When branch choice is ambiguous, execute:

```bash
hal continue --json
```

and follow `nextCommand`.

---

## 4) Ship Policy (`manual_complete`)

Run:

```bash
hal review --base <base-branch>
```

If `HAS_CI`:

```bash
hal ci push
hal ci status --wait
# if failing:
hal ci fix
hal ci status --wait
# when green:
hal ci merge
```

Then finalize:

```bash
hal archive
```

If `HAS_CI` is false, stop after review and report manual CI/merge handoff steps.

---

## 5) CI Failure Protocol

On CI failure:
1. `hal ci status --json` → collect failing checks
2. `hal ci fix`
3. `hal ci status --wait`
4. Repeat per configured policy/max attempts
5. If still failing, stop and report:
   - failed checks
   - top error signatures
   - likely impacted files/components

---

## 6) Intent Shortcuts

### Intent: build new feature
```bash
hal doctor --json
hal status --json
hal plan "<feature>"
hal auto
```

### Intent: resume interrupted auto run
```bash
hal auto --resume
```

### Intent: ship current branch
```bash
hal review --base <base-branch>
# run CI policy if available
hal archive
```

### Intent: continuous report-driven development
```bash
hal report
# then COMPOUND_ENTRY_CMD
```

---

## 7) Agent Checkpoint Format

After each major command, emit a short update:

- `state:` current `status.state`
- `command:` command just run
- `result:` success/failure + one-line reason
- `next:` next command

Keep updates compact. Decisions must be contract-driven and reproducible.
