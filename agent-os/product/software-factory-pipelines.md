# Hal Software Factory — Pipeline Design

> Every pipeline is a sequence of hal commands. Nothing more.

---

## 1. The Three Pipeline Tiers

```
Tier 1: MANUAL         — Human drives hal commands one at a time
Tier 2: COMPOUND       — hal auto drives the full cycle, human approves
Tier 3: FACTORY        — Web UI drives hal, PM approves at gates
```

Each tier uses the **exact same commands** — the difference is who's calling them and where the approval gates live.

---

## 2. Complete Command Map

Every hal command, where it fits, and what it produces:

```
PLANNING                    EXECUTION                   CLOSING
────────                    ─────────                   ───────
hal plan ──→ prd-*.md       hal run ──→ commits         hal ci push ──→ remote branch
hal convert ──→ prd.json    hal review ──→ fixes         hal ci status ──→ CI result
hal validate ──→ pass/fail  hal report ──→ report.md     hal ci fix ──→ CI fix commits
hal explode ──→ auto-prd    hal analyze ──→ next item    hal ci merge ──→ merged PR

LIFECYCLE                   OBSERVABILITY
─────────                   ─────────────
hal init                    hal status ──→ workflow state
hal archive ──→ snapshot    hal doctor ──→ env health
hal cleanup                 hal continue ──→ next action
hal sandbox *               hal prd audit ──→ PRD health
```

---

## 3. Pipeline Definitions

### Pipeline A: Manual (human at the wheel)

```
human: hal init
human: hal plan "feature X"
human: hal convert
human: hal validate        ← optional but recommended
human: hal run
human: hal review --base main
human: hal ci push
human: hal ci status       ← wait for green
human: hal ci fix          ← if CI fails, loop
human: hal ci merge
human: hal archive
```

**Who calls what:** Human types every command.
**Gates:** Human judgment between every step.
**State files:** prd-*.md → prd.json → progress.txt → archive/

---

### Pipeline B: Compound (`hal auto` — current)

```
hal auto
  ├─ step 1: analyze     ← find latest report, pick priority item
  ├─ step 2: branch      ← create feature branch
  ├─ step 3: prd         ← autospec skill generates PRD
  ├─ step 4: explode     ← break into 8-15 granular tasks
  ├─ step 5: loop        ← hal run until all tasks pass
  ├─ step 6: pr          ← push + create draft PR   ← THIS IS THE PROTO hal ci
  └─ state: auto-state.json (resumable)

hal review --base <branch>   ← separate command, run after auto
hal report                   ← generates input for next auto cycle
```

**Who calls what:** Human kicks off `hal auto`, hal drives everything.
**Gates:** None during execution. Human reviews the draft PR after.
**Gap:** No CI checking. No review integration in the auto pipeline. No merge.

---

### Pipeline C: Factory (the full loop)

This is what the web product runs, but it's also what a **skill** can drive:

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  PLAN ──→ VALIDATE ──→ EXECUTE ──→ REVIEW ──→ CI ──→ MERGE     │
│                                                                 │
│  hal plan          hal run         hal ci push                  │
│  hal convert       hal review      hal ci status                │
│  hal validate                      hal ci fix                   │
│  (hal explode)                     hal ci merge                 │
│                                                                 │
│  ◄──── hal report + hal analyze = next spec ────►               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Detailed step sequence:**

```
PHASE 1: PLAN
  1. hal plan "feature X" -f json     ← or: hal plan → hal convert
  2. hal validate                     ← check PRD quality
     └─ if fails → hal convert --force (re-generate)
     └─ loop up to 3 times
  3. [GATE: human approves PRD]

PHASE 2: EXECUTE
  4. hal run --base main              ← develop all stories
     └─ reads progress.txt, resumes from where it left off
  5. hal review --base main           ← AI reviews its own code
     └─ iterates until no valid issues or max iterations

PHASE 3: SHIP
  6. hal ci push                      ← push branch, open draft PR
  7. hal ci status                    ← poll CI checks
     └─ if fails:
        8. hal ci fix                 ← parse CI output, fix, commit
        9. goto 7                     ← re-check (max 3 loops)
  10. [GATE: human approves PR]
  11. hal ci merge                    ← merge PR

PHASE 4: NEXT (optional, compound loop)
  12. hal report                      ← summarize what was built
  13. hal analyze                     ← pick next priority from report
  14. goto PHASE 1 with new spec
```

---

## 4. `hal ci` — Spec

### Commands

```
hal ci push      Push branch and open draft PR
hal ci status    Check CI/CD pipeline results
hal ci fix       Read CI failures, generate fixes, push
hal ci merge     Merge PR when CI is green
hal ci link      Show PR URL for current branch
```

### `hal ci push`

```bash
hal ci push                     # Push current branch, open draft PR against base
hal ci push --base develop      # Explicit base branch
hal ci push --title "feat: X"   # Custom PR title (default: from prd.json)
hal ci push --body-from report  # PR body from latest hal report
hal ci push --json              # Machine-readable output
hal ci push --dry-run           # Show what would happen
```

**Behavior:**
1. Read `prd.json` for branch name, feature title, story summary
2. `git push -u origin <branch>`
3. Create draft PR via GitHub API (`go-github`) or `gh` CLI fallback
4. PR title defaults to prd.json `featureName`
5. PR body auto-generated from: feature description + completed stories + review summary
6. Output: PR URL, PR number, CI status URL

**Implementation:** `internal/ci/push.go`
- Detect GitHub remote from `git remote -v`
- Prefer `go-github` client, fallback to `gh` CLI
- Auth: `$GITHUB_TOKEN` or `gh auth status`

### `hal ci status`

```bash
hal ci status                   # Check CI for current branch's PR
hal ci status --wait            # Poll until CI completes (with timeout)
hal ci status --wait --timeout 10m
hal ci status --json
```

**Behavior:**
1. Find PR for current branch
2. Fetch check suite / workflow run status
3. Report: pending / passing / failing (with failed check names)
4. `--wait`: poll every 30s until terminal state

**Output (JSON):**
```json
{
  "pr": {"number": 42, "url": "..."},
  "checks": {
    "status": "failing",
    "passed": ["lint", "typecheck"],
    "failed": ["test-unit"],
    "pending": []
  },
  "failureLog": "FAIL TestFoo: expected 3, got 5..."
}
```

### `hal ci fix`

```bash
hal ci fix                      # Auto-fix CI failures
hal ci fix --max-attempts 3     # Max fix iterations (default: 3)
hal ci fix --json
```

**Behavior:**
1. Run `hal ci status --json` to get failure details
2. Download failed check logs via GitHub API
3. Parse failure into a mini-fix prompt:
   - Test failures → "fix failing test: <error>"
   - Lint errors → "fix lint: <file>:<line> <message>"
   - Type errors → "fix type error: <details>"
   - Build failures → "fix build: <error>"
4. Run the fix through the engine (single focused iteration)
5. `git add -A && git commit -m "fix: CI failure in <check>"`
6. `git push`
7. Wait for CI re-run → `hal ci status --wait`
8. If still failing and attempts < max, goto 1

**Key design:** This is NOT a full `hal run`. It's a single-shot fix using the engine
with a very focused prompt. The CI log IS the acceptance criterion.

### `hal ci merge`

```bash
hal ci merge                    # Merge PR (squash by default)
hal ci merge --strategy rebase  # rebase / merge / squash
hal ci merge --json
hal ci merge --dry-run
```

**Behavior:**
1. Check CI is green (`hal ci status`)
2. If not green, refuse (suggest `hal ci fix`)
3. Merge via GitHub API
4. Delete remote branch
5. Optionally run `hal archive` locally

### Architecture

```
cmd/ci.go                           ← Cobra parent + subcommands
cmd/ci_push.go
cmd/ci_status.go
cmd/ci_fix.go
cmd/ci_merge.go

internal/ci/
  github.go                         ← GitHub API client (PRs, checks, merge)
  gh_fallback.go                    ← gh CLI fallback when no GITHUB_TOKEN
  push.go                           ← Branch push + PR creation logic
  status.go                         ← CI check polling
  fix.go                            ← Failure parsing + fix loop
  merge.go                          ← PR merge logic
  types.go                          ← CIResult, PRInfo, CheckStatus
```

---

## 5. Pipeline Presets (for web + skill)

These map directly to the web spec's presets, but defined as hal-native sequences:

```yaml
# .hal/config.yaml additions
pipeline:
  preset: with_review   # simple | with_review | with_approval | compound | continuous

  # Or custom stages:
  stages:
    - execute
    - review
    - gate          # human approval
    - ci_push
    - ci_wait
    - ci_fix        # auto-fix CI failures (max 3 attempts)
    - ci_merge
```

### Preset Definitions

**simple:**
```
execute → ci_push → ci_wait → ci_merge
```

**with_review:**
```
execute → review → ci_push → ci_wait → ci_fix → ci_merge
```

**with_approval:**
```
execute → review → GATE → ci_push → ci_wait → ci_fix → ci_merge
```

**compound:**
```
execute → review → report → GATE → ci_push → ci_wait → ci_fix → ci_merge
```

**continuous:**
```
execute → review → report → GATE → ci_push → ci_wait → ci_fix → ci_merge
  → analyze → GATE → [next spec] → execute → ...
```

---

## 6. How `hal auto` Evolves

Current `hal auto` pipeline:
```
analyze → branch → prd → explode → loop → pr
```

Proposed evolution — `hal auto` becomes pipeline-aware:

```
analyze → branch → prd → validate → explode → loop → review → ci_push → ci_wait → ci_fix → ci_merge
                           ↑ NEW     (already)  (already)  ↑ NEW (replaces pr step)
```

**Migration path:**
1. Current `pr` step in pipeline.go already does `git push` + `gh pr create`
2. Replace with `hal ci push` internally
3. Add `ci_wait` + `ci_fix` + `ci_merge` as new pipeline steps
4. Add `review` step between `loop` and `ci_push`
5. Add `validate` step between `prd` and `explode`
6. Pipeline steps become configurable via preset

**New pipeline steps enum:**
```go
const (
    StepAnalyze  PipelineStep = "analyze"
    StepBranch   PipelineStep = "branch"
    StepPRD      PipelineStep = "prd"
    StepValidate PipelineStep = "validate"   // NEW
    StepExplode  PipelineStep = "explode"
    StepLoop     PipelineStep = "loop"
    StepReview   PipelineStep = "review"     // NEW
    StepCIPush   PipelineStep = "ci_push"    // NEW (replaces StepPR)
    StepCIWait   PipelineStep = "ci_wait"    // NEW
    StepCIFix    PipelineStep = "ci_fix"     // NEW
    StepCIMerge  PipelineStep = "ci_merge"   // NEW
    StepReport   PipelineStep = "report"     // NEW
    StepGate     PipelineStep = "gate"       // NEW (web/agent approval)
    StepDone     PipelineStep = "done"
)
```

---

## 7. The Developer Skill

A SKILL.md that teaches any coding agent how to drive hal. This is **not** a framework — it's a recipe.

### When to use which pipeline:

```
TASK: "Build feature X from scratch"
→ Full pipeline: plan → convert → validate → run → review → ci

TASK: "Fix this bug"
→ Minimal pipeline: (manual edit or single hal run -s US-001) → ci push

TASK: "Build the next thing from the report"
→ Compound: hal auto (handles analyze → branch → prd → execute → ci)

TASK: "Review and ship what's on this branch"
→ Closing pipeline: hal review → hal ci push → hal ci status → hal ci merge
```

### Key skill behaviors:
1. Always check `hal status --json` first to understand current state
2. Always check `hal doctor --json` before starting work
3. If doctor has issues, run `hal repair` first
4. Use `hal continue --json` to determine next action when unsure
5. All hal commands support `--json` for machine-readable output
6. `prd.json` is the source of truth for task status
7. `progress.txt` is the human-readable log
8. `auto-state.json` tracks compound pipeline position

### Skill decision tree:

```
START
  │
  ├─ hal doctor --json
  │   └─ issues? → hal repair → retry
  │
  ├─ hal status --json
  │   ├─ not_initialized → hal init
  │   ├─ hal_initialized_no_prd → hal plan → hal convert
  │   ├─ manual_in_progress → hal run
  │   ├─ manual_complete → hal review → hal ci push
  │   ├─ compound_active → hal auto --resume
  │   └─ compound_complete → hal ci push (if not already)
  │
  ├─ After hal run completes:
  │   └─ hal review --base <base> → hal ci push → hal ci status
  │       └─ CI fails? → hal ci fix
  │       └─ CI green? → hal ci merge → hal archive
  │
  └─ After hal ci merge:
      └─ hal report → done (or hal auto for next feature)
```

---

## 8. The Agent (for `hal serve` / web)

The agent is NOT a separate AI system. It's a **state machine** that calls hal commands:

```go
type FactoryAgent struct {
    project    *Project
    sandbox    *sandbox.Instance
    pipeline   []PipelineStep
    current    int
    gateAction chan GateAction  // blocks at gates until human acts
}

func (a *FactoryAgent) Run(ctx context.Context) error {
    for a.current < len(a.pipeline) {
        step := a.pipeline[a.current]

        if step == StepGate {
            action := <-a.gateAction  // wait for human
            if action == Reject { return ErrRejected }
            if action == Retry { a.current--; continue }
        }

        err := a.executeStep(ctx, step)
        if err != nil {
            return err  // web UI shows error, offers retry
        }

        a.current++
        a.saveState()
    }
    return nil
}

func (a *FactoryAgent) executeStep(ctx context.Context, step PipelineStep) error {
    // Every step is just: SSH into sandbox, run hal command, parse JSON output
    switch step {
    case StepExecute:
        return a.sandbox.Exec(ctx, "hal", "run", "--json")
    case StepReview:
        return a.sandbox.Exec(ctx, "hal", "review", "--base", a.project.DefaultBranch, "--json")
    case StepCIPush:
        return a.sandbox.Exec(ctx, "hal", "ci", "push", "--json")
    case StepCIWait:
        return a.sandbox.Exec(ctx, "hal", "ci", "status", "--wait", "--json")
    case StepCIFix:
        return a.sandbox.Exec(ctx, "hal", "ci", "fix", "--json")
    case StepCIMerge:
        return a.sandbox.Exec(ctx, "hal", "ci", "merge", "--json")
    case StepReport:
        return a.sandbox.Exec(ctx, "hal", "report", "--json")
    }
}
```

**The agent is 50 lines of Go.** Everything else is hal commands.

---

## 9. What Needs Building (Priority Order)

### Now: `hal ci` (the missing tooth)
```
internal/ci/          ← GitHub API, push, status, fix, merge
cmd/ci*.go            ← CLI commands
```
**Why first:** Closes the loop. Both manual and auto workflows need it. The skill needs it. The web product needs it.

### Next: Developer Skill
```
.pi/skills/factory/SKILL.md    ← teaches agents to drive hal end-to-end
```
**Why second:** Makes hal useful with any coding agent today. Zero infrastructure needed.

### Then: Pipeline Evolution
```
internal/compound/pipeline.go  ← add validate, review, ci_*, report, gate steps
cmd/auto.go                    ← wire new steps, support presets
.hal/config.yaml               ← pipeline preset configuration
```
**Why third:** Upgrades `hal auto` from "run + PR" to "run + review + CI + merge."

### Finally: `hal serve` + Web
```
cmd/serve.go                   ← HTTP server
internal/api/                  ← REST + WebSocket handlers
internal/factory/              ← FactoryAgent state machine
web/                           ← Next.js frontend
```
**Why last:** The CLI and skill prove the pipeline works. The web product is a UI on top.

---

## 10. State Flow Diagram

How state files flow through the factory:

```
INPUT                    hal COMMAND          STATE PRODUCED
─────                    ───────────          ──────────────
feature description  →   hal plan         →   .hal/prd-feature.md
prd-feature.md       →   hal convert      →   .hal/prd.json
prd.json             →   hal validate     →   pass/fail (stdout)
prd.json             →   hal explode      →   .hal/auto-prd.json
prd.json             →   hal run          →   .hal/progress.txt + git commits
                                               prd.json (stories marked pass)
git diff             →   hal review       →   fix commits + review report
                     →   hal ci push      →   remote branch + draft PR
PR                   →   hal ci status    →   CI result (pass/fail/pending)
CI failure logs      →   hal ci fix       →   fix commits + push
green CI             →   hal ci merge     →   merged PR + deleted branch
completed work       →   hal report       →   .hal/reports/report-*.md
report               →   hal analyze      →   priority item (JSON)
priority item        →   hal auto         →   .hal/auto-state.json
                                               (drives full cycle)
```

Every command reads state files and produces state files. The pipeline is just **the order you call them in.**
