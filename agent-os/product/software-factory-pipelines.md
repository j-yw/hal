# Hal Software Factory — Pipeline Design

> Every pipeline is a sequence of hal commands. Nothing more.

---

## 1. The Two Pipeline Modes

```
MANUAL     — Human drives hal commands one at a time
AUTO       — hal auto drives the full cycle from PRD to merge
```

`hal auto` has two entry points:
- **Default:** Start from a `prd-*.md` (written by human via `hal plan`, or provided directly)
- **Compound loop (`--compound`):** Start from a `hal report`, analyze it, generate the PRD, then execute

Both entry points converge into the same pipeline: convert → validate → run → review → CI → merge.

---

## 2. Complete Command Map

```
PLANNING                    EXECUTION                   CLOSING
────────                    ─────────                   ───────
hal plan ──→ prd-*.md       hal run ──→ commits         hal ci push ──→ remote branch
hal convert ──→ prd.json    hal review ──→ fixes         hal ci status ──→ CI result
hal validate ──→ pass/fail  hal report ──→ report.md     hal ci fix ──→ CI fix commits
                            hal analyze ──→ next item    hal ci merge ──→ merged PR

LIFECYCLE                   OBSERVABILITY
─────────                   ─────────────
hal init                    hal status ──→ workflow state
hal archive ──→ snapshot    hal doctor ──→ env health
hal cleanup                 hal continue ──→ next action
hal sandbox *               hal prd audit ──→ PRD health
```

**Removed:** `hal explode` is deprecated. Its behavior is absorbed into `hal convert --granular`.

---

## 3. Pipeline Definitions

### Pipeline A: Manual (human at the wheel)

```
hal init
hal plan "feature X"
hal convert                    ← prd-*.md → prd.json (US-XXX stories)
hal validate                   ← optional but recommended
hal run
hal review --base main
hal ci push
hal ci status                  ← wait for green
hal ci fix                     ← if CI fails, loop
hal ci merge
hal archive
```

**Who calls what:** Human types every command.
**Gates:** Human judgment between every step.
**State files:** prd-*.md → prd.json → progress.txt → archive/

---

### Pipeline B: Auto — default (from PRD)

```
hal auto                         # discover prd-*.md, execute everything
hal auto prd-auth.md             # use specific markdown
hal auto --resume                # resume from saved state
```

**Pipeline steps:**

```
discover prd-*.md (newest by mtime, or explicit arg)
  │
branch:    create hal/<feature> branch
  │
convert:   prd-*.md → prd.json (granular: 8-15 T-XXX tasks)
  │
validate:  check prd.json quality
  │         └─ fails → re-convert with error feedback (max 3 attempts)
  │
run:       execute all tasks
  │
review:    hal review --base <base>
  │
report:    generate summary report (while still on feature branch)
  │
ci:        push → open PR → wait for CI → fix if needed → merge
  │
archive:   archive completed feature state
  │
done
```

**Who calls what:** Human kicks off `hal auto`, hal drives everything.
**Gates:** None. Fully autonomous from PRD to merged PR.

---

### Pipeline C: Auto — compound loop (from report)

```
hal auto --compound                    # analyze latest report, generate PRD, execute
hal auto --compound --report report.md # use specific report
hal auto --compound --resume           # resume from saved state
```

**Pipeline steps:**

```
analyze:   find latest report, extract priority item
  │
spec:      autospec generates prd-*.md from analysis
  │
  ▼
[SAME AS PIPELINE B FROM HERE]
branch → convert → validate → run → review → report → ci → archive → done
```

**This is the continuous development loop:**

```
hal report → hal auto --compound → (builds feature) → hal report → hal auto --compound → ...
```

Each cycle:
1. `hal report` summarizes current codebase state, identifies improvements
2. `hal auto --compound` reads report, picks priority, builds it, ships it
3. New `hal report` reflects the changes — next cycle picks up the next priority

---

## 4. The Unified Pipeline (shared by B and C)

Both auto modes converge here. This is the engine:

```go
const (
    // Entry steps (Pipeline C only — compound loop)
    StepAnalyze  = "analyze"     // Find report, extract priority
    StepSpec     = "spec"        // Generate prd-*.md from analysis

    // Common flow (Pipeline B starts here)
    StepBranch   = "branch"      // Create feature branch
    StepConvert  = "convert"     // prd-*.md → prd.json (granular)
    StepValidate = "validate"    // Validate prd.json, fix loop if needed
    StepRun      = "run"         // Execute all tasks
    StepReview   = "review"      // AI review + fix loop
    StepReport   = "report"      // Generate summary (on feature branch)
    StepCI       = "ci"          // Push → wait → fix → merge
    StepArchive  = "archive"     // Archive completed feature state
    StepDone     = "done"
)
```

### Pipeline State

```go
type PipelineState struct {
    Step              string          `json:"step"`
    EntryMode         string          `json:"entryMode"`           // "prd" or "compound"
    BaseBranch        string          `json:"baseBranch,omitempty"`
    BranchName        string          `json:"branchName"`
    SourceMarkdown    string          `json:"sourceMarkdown"`      // prd-*.md path
    ReportPath        string          `json:"reportPath,omitempty"`
    StartedAt         time.Time       `json:"startedAt"`

    // Convert/validate state
    ValidateAttempts  int             `json:"validateAttempts,omitempty"`

    // Run state
    RunIterations     int             `json:"runIterations,omitempty"`
    RunComplete       bool            `json:"runComplete,omitempty"`

    // CI state
    CIAttempts        int             `json:"ciAttempts,omitempty"`
    PRUrl             string          `json:"prUrl,omitempty"`

    // Compound-only
    Analysis          *AnalysisResult `json:"analysis,omitempty"`
}
```

### Step Details

#### `branch`
Create and checkout `hal/<feature>` from base branch.
- Branch name derived from: prd-*.md filename (default mode) or analysis.BranchName (compound mode)
- If branch already exists (resume), just checkout

#### `convert`
Run `hal convert --granular` internally: prd-*.md → prd.json with 8-15 atomic T-XXX tasks.
- Uses merged convert skill (absorbs explode skill behavior)
- Output always writes to `.hal/prd.json` — no more `auto-prd.json`
- `--granular` enforces: 8-15 tasks, T-XXX IDs, one-iteration sizing, boolean criteria

#### `validate`
Run `hal validate` on the generated prd.json. If validation fails:
1. Feed validation errors back to the engine with the original markdown
2. Re-run convert with fix instructions
3. Re-validate (max 3 total attempts)
4. If still failing after 3 attempts, abort with error

```
convert → validate → PASS → continue
                  → FAIL → reconvert with errors → validate → PASS → continue
                                                            → FAIL → reconvert → validate → PASS/ABORT
```

#### `run`
Execute `hal run --json`. The loop runner reads prd.json, picks next pending task, executes, marks done, repeats.
- Resumes from where it left off (completed tasks stay completed)
- Max iterations from config (default 50 for auto)

#### `review`
Execute `hal review --base <base-branch> --json`. The review loop:
1. Diffs feature branch against base
2. AI reviews the diff, finds issues
3. Validates issues, auto-fixes what it can
4. Repeats until no valid issues or max iterations

#### `report`
Execute `hal report --json` **while still on the feature branch.**
- Generates `.hal/reports/report-*.md` with summary of what was built
- Updates AGENTS.md with discovered patterns
- Must run before CI push so the report captures full context (diff, commits, progress)
- Report is included in the PR body

#### `ci`
Single step that handles the full CI lifecycle internally:

```
push branch → open draft PR → wait for CI → [fix loop] → merge
```

Internally:
1. `git push -u origin <branch>`
2. Create draft PR (title from prd.json, body from report)
3. Poll CI checks (30s interval, 30min timeout)
4. If CI fails:
   a. Download failure logs
   b. Single-shot engine fix (focused prompt with CI error)
   c. Commit + push
   d. Re-poll CI (max 3 fix attempts)
5. If CI green: merge PR (squash default)
6. Delete remote branch

This is one pipeline step because the sub-steps (push/wait/fix/merge) are a tight retry loop, not independent resumable steps. State tracks `CIAttempts` for resume.

#### `archive`
Run `hal archive create` to snapshot completed feature state before returning to base branch.

---

## 5. `hal convert` — Unified Conversion

### Absorbing `hal explode`

`hal convert` becomes the single command for markdown → JSON:

```bash
hal convert                          # prd-*.md → prd.json (US-XXX stories)
hal convert .hal/prd-auth.md         # explicit source
hal convert --granular               # 8-15 atomic tasks, T-XXX IDs
hal convert --granular --json        # machine-readable output
```

**Without `--granular`:** Standard conversion. US-XXX story IDs, developer-sized stories. For manual workflow where humans supervise each story.

**With `--granular`:** Atomic decomposition. T-XXX task IDs, 8-15 tasks enforced, each completable in one agent iteration. For auto workflow.

`hal auto` always uses `--granular` internally.

### Skill Merge

The current `hal` skill and `explode` skill merge into one convert skill with a mode parameter:

```markdown
## Conversion Modes

### Standard Mode (default)
- US-XXX IDs, developer-sized stories
- No strict count constraint
- Stories may span multiple files

### Granular Mode (--granular)
- T-XXX IDs, one-iteration atomic tasks
- 8-15 tasks enforced
- Each task: one function, one struct, one component
- Dependency-ordered: types → logic → integration → verification
```

### Deprecation

`hal explode` becomes a deprecated alias:
```
hal explode prd.md  →  prints deprecation warning  →  runs hal convert --granular prd.md
```

Remove in v1.0.

### File Unification

**Kill `auto-prd.json`.** Everything writes to `prd.json`.

The loop runner already takes `PRDFile` as a config param — it doesn't care about the filename. After this change:
- Manual workflow: `hal convert` → prd.json (US-XXX)
- Auto workflow: `hal convert --granular` → prd.json (T-XXX)
- `hal run` reads prd.json in both cases

Migration: if `auto-prd.json` exists and `prd.json` doesn't, rename it. Add to `hal cleanup` orphan list.

---

## 6. `hal ci` — Spec

### Commands

```
hal ci push      Push branch and open draft PR
hal ci status    Check CI/CD pipeline results
hal ci fix       Read CI failures, generate fixes, push
hal ci merge     Merge PR when CI is green
```

### `hal ci push`

```bash
hal ci push                          # Push current branch, open draft PR
hal ci push --base develop           # Explicit base branch
hal ci push --title "feat: auth"     # Custom PR title (default: from prd.json)
hal ci push --body-from report       # PR body from latest hal report
hal ci push --json                   # Machine-readable output
hal ci push --dry-run                # Show what would happen
```

**Behavior:**
1. Read `prd.json` for branch name, feature title, story summary
2. `git push -u origin <branch>`
3. Create draft PR via `go-github` client (fallback: `gh` CLI)
4. PR title defaults to prd.json feature name
5. PR body: feature description + completed stories + report summary (if available)
6. Output: PR URL, PR number

**Auth:** `$GITHUB_TOKEN` → `gh auth token` fallback

**JSON output:**
```json
{
  "contractVersion": 1,
  "ok": true,
  "pr": {"number": 42, "url": "https://github.com/org/repo/pull/42"},
  "branch": "hal/user-auth"
}
```

### `hal ci status`

```bash
hal ci status                        # Check CI for current branch
hal ci status --wait                 # Poll until CI completes
hal ci status --wait --timeout 30m   # With timeout (default: 30m)
hal ci status --json
```

**Behavior:**
1. Find PR for current branch (by head ref)
2. Fetch check suite / workflow run status
3. Report: pending / passing / failing (with failed check names + logs)
4. `--wait`: poll every 30s until terminal state or timeout

**JSON output:**
```json
{
  "contractVersion": 1,
  "ok": true,
  "pr": {"number": 42, "url": "..."},
  "status": "failing",
  "checks": {
    "passed": ["lint", "typecheck"],
    "failed": ["test-unit"],
    "pending": []
  },
  "failureLogs": {
    "test-unit": "FAIL TestFoo: expected 3, got 5\n..."
  }
}
```

### `hal ci fix`

```bash
hal ci fix                           # Auto-fix CI failures
hal ci fix --max-attempts 3          # Max fix iterations (default: 3)
hal ci fix -e claude                 # Use specific engine
hal ci fix --json
```

**Behavior:**
1. Run `hal ci status --json` to get failures
2. Download failed check logs via GitHub API
3. Parse failure into a focused fix prompt:
   - Test failures → "fix failing test: <error output>"
   - Lint errors → "fix lint: <file>:<line> <message>"
   - Type errors → "fix type error: <details>"
   - Build failures → "fix build: <error>"
4. Single-shot engine invocation (NOT `hal run` — no PRD story, just a focused fix)
5. `git add -A && git commit -m "fix: CI failure in <check-name>"`
6. `git push`
7. `hal ci status --wait` to verify fix
8. If still failing and attempts < max, goto 1

**Key design decision:** `hal ci fix` uses a **single-shot engine prompt**, not the loop runner. The engine gets the CI error as context and the codebase as workspace. This is closer to how `hal review` works than how `hal run` works.

### `hal ci merge`

```bash
hal ci merge                         # Merge PR (squash default)
hal ci merge --strategy rebase       # rebase / merge / squash
hal ci merge --delete-branch=false   # Keep remote branch
hal ci merge --json
hal ci merge --dry-run
```

**Behavior:**
1. Check CI is green (`hal ci status`)
2. If not green, refuse with error: "CI checks failing, run `hal ci fix` first"
3. Merge PR via GitHub API (squash default)
4. Delete remote branch (unless `--delete-branch=false`)
5. Checkout base branch locally

### Architecture

```
cmd/ci.go                           ← Cobra parent command
cmd/ci_push.go                      ← hal ci push
cmd/ci_status.go                    ← hal ci status
cmd/ci_fix.go                       ← hal ci fix
cmd/ci_merge.go                     ← hal ci merge

internal/ci/
  github.go                         ← GitHub API client wrapper
  gh_fallback.go                    ← gh CLI fallback for auth + API
  push.go                           ← PushAndCreatePR(opts) logic
  status.go                         ← GetCheckStatus / WaitForChecks
  fix.go                            ← ParseFailures + single-shot fix loop
  merge.go                          ← MergePR logic
  types.go                          ← PushResult, CheckResult, PRInfo
```

`internal/ci/` exports Go functions that both `cmd/ci_*.go` and `internal/compound/pipeline.go` call directly. No shelling out to self.

---

## 7. `hal auto` — Unified Design

### CLI Interface

```bash
# Default mode: from PRD
hal auto                             # Discover prd-*.md, run full pipeline
hal auto .hal/prd-auth.md            # Use specific markdown
hal auto --base develop              # Explicit base branch
hal auto --resume                    # Resume from saved state
hal auto --dry-run                   # Show what would happen
hal auto --skip-ci                   # Stop after review (no push/merge)
hal auto --json                      # Machine-readable output
hal auto -e claude                   # Use specific engine

# Compound mode: from report
hal auto --compound                  # Analyze latest report first
hal auto --compound --report r.md    # Use specific report
```

### Behavior

**Default mode (`hal auto`):**
1. Find `prd-*.md` (newest by mtime, or positional arg)
2. If no markdown found: error with "run `hal plan` first or provide a path"
3. Start pipeline at `StepBranch`

**Compound mode (`hal auto --compound`):**
1. Find latest report in `.hal/reports/`
2. Analyze report → extract priority item
3. Generate `prd-*.md` via autospec skill
4. Start pipeline at `StepBranch` (same as default from here)

**Resume (`hal auto --resume`):**
1. Load `auto-state.json`
2. Continue from saved step
3. Entry mode preserved in state

### Flags Replacing Current Behavior

| Current flag | New equivalent | Notes |
|---|---|---|
| `--report report.md` | `--compound --report report.md` | Report implies compound mode |
| `--skip-pr` | `--skip-ci` | Renamed for clarity |
| (new) | `--compound` | Activates analyze → spec entry |
| (removed) | ~~`--skip-pr`~~ | Replaced by `--skip-ci` |

---

## 8. Pipeline Presets (for web + skill)

These define reusable pipeline configurations:

```yaml
# .hal/config.yaml
auto:
  preset: full   # minimal | standard | full | continuous
```

### Preset Definitions

**minimal** — just build and push:
```
branch → convert → run → ci
```

**standard** (default) — build, review, ship:
```
branch → convert → validate → run → review → report → ci → archive
```

**full** — standard with approval gate (web/skill only):
```
branch → convert → validate → run → review → report → GATE → ci → archive
```

**continuous** — compound loop with gates:
```
analyze → spec → branch → convert → validate → run → review → report
  → GATE → ci → archive → [next report] → analyze → ...
```

Gates are only meaningful in the web product or skill-driven flows. `hal auto` CLI ignores gate steps (no way to block in a terminal).

---

## 9. The Developer Skill

A SKILL.md that teaches any coding agent how to drive hal end-to-end.

### Decision Tree

```
START
  │
  ├─ hal doctor --json
  │   └─ issues? → hal repair → retry
  │
  ├─ hal status --json
  │   │
  │   ├─ not_initialized
  │   │   └─ hal init
  │   │
  │   ├─ hal_initialized_no_prd
  │   │   └─ Do we have requirements?
  │   │       ├─ yes → hal plan "..." → hal auto
  │   │       └─ no  → ask user for requirements
  │   │
  │   ├─ manual_in_progress (prd.json exists, stories pending)
  │   │   └─ hal auto              ← takes over from manual workflow
  │   │
  │   ├─ manual_complete (all stories passed)
  │   │   └─ hal review --base <base> → hal ci push → hal ci status
  │   │       └─ CI fails? → hal ci fix
  │   │       └─ CI green? → hal ci merge → hal archive
  │   │
  │   ├─ compound_active (auto-state.json exists)
  │   │   └─ hal auto --resume
  │   │
  │   └─ compound_complete
  │       └─ hal report → done
  │           └─ want next feature? → hal auto --compound
  │
  └─ DONE
```

### When to Use Which Flow

```
TASK: "Build feature X from scratch"
  → hal plan "X" → hal auto

TASK: "Fix this bug"
  → manual edit or hal run -s US-001 → hal ci push → hal ci merge

TASK: "Continue building from where we left off"
  → hal auto --resume

TASK: "Build the next thing from the report"
  → hal auto --compound

TASK: "Review and ship what's on this branch"
  → hal review --base main → hal ci push → hal ci merge

TASK: "Set up continuous development loop"
  → hal report → hal auto --compound → (repeat)
```

### Key Skill Rules
1. Always `hal status --json` first — understand current state
2. Always `hal doctor --json` before starting — fix env issues
3. If unsure: `hal continue --json` recommends the next action
4. All commands support `--json` for machine-readable output
5. `prd.json` is the single source of truth for task status
6. `progress.txt` is the append-only human-readable log
7. `auto-state.json` tracks pipeline position for resume

---

## 10. The Agent (for `hal serve` / web)

The agent is a **state machine** that calls hal commands. Not an AI system.

```go
type FactoryAgent struct {
    project    *Project
    sandbox    *sandbox.Instance
    pipeline   []PipelineStep
    current    int
    gateAction chan GateAction
}

func (a *FactoryAgent) Run(ctx context.Context) error {
    for a.current < len(a.pipeline) {
        step := a.pipeline[a.current]

        if step == StepGate {
            action := <-a.gateAction  // blocks until PM acts
            switch action {
            case Reject:
                return ErrRejected
            case Retry:
                a.current--
                continue
            }
        }

        err := a.executeStep(ctx, step)
        if err != nil {
            return err  // web shows error, offers retry
        }

        a.current++
        a.saveState()
    }
    return nil
}

func (a *FactoryAgent) executeStep(ctx context.Context, step PipelineStep) error {
    // Every step = SSH into sandbox + run hal command + parse JSON
    switch step {
    case StepRun:
        return a.sandbox.Exec(ctx, "hal", "run", "--json")
    case StepReview:
        return a.sandbox.Exec(ctx, "hal", "review", "--base", a.baseBranch, "--json")
    case StepReport:
        return a.sandbox.Exec(ctx, "hal", "report", "--json")
    case StepCI:
        return a.sandbox.Exec(ctx, "hal", "auto", "--skip-to", "ci", "--json")
    // ... etc
    }
}
```

**50 lines of Go.** The intelligence is in hal. The agent is just a for loop.

---

## 11. State Flow Diagram

```
INPUT                    hal COMMAND              STATE PRODUCED
─────                    ───────────              ──────────────
feature description  →   hal plan             →   .hal/prd-feature.md
prd-feature.md       →   hal convert           →   .hal/prd.json (US-XXX)
prd-feature.md       →   hal convert --granular →   .hal/prd.json (T-XXX)
prd.json             →   hal validate          →   pass/fail (stdout)
prd.json             →   hal run               →   .hal/progress.txt + commits
                                                    prd.json (stories marked pass)
git diff             →   hal review            →   fix commits + review report
completed work       →   hal report            →   .hal/reports/report-*.md
feature branch       →   hal ci push           →   remote branch + draft PR
PR                   →   hal ci status         →   CI result (pass/fail)
CI failure logs      →   hal ci fix            →   fix commits + push
green CI             →   hal ci merge          →   merged PR
completed feature    →   hal archive           →   .hal/archive/<date>-<feature>/
report               →   hal analyze           →   priority item (JSON)
report               →   hal auto --compound   →   .hal/auto-state.json
prd-*.md             →   hal auto              →   .hal/auto-state.json
```

---

## 12. Migration & Deprecation

### Immediate (next release)

| Change | Details |
|---|---|
| `hal convert --granular` | New flag, absorbs explode behavior |
| `hal explode` | Deprecated alias → `hal convert --granular` + warning |
| `auto-prd.json` | Pipeline internals write to `prd.json` instead |
| `hal auto --compound` | New flag for report-driven entry |
| `hal auto --skip-ci` | Replaces `--skip-pr` |

### v1.0 (removal)

| Removal | Replacement |
|---|---|
| `hal explode` command | `hal convert --granular` |
| `auto-prd.json` file | `prd.json` |
| `--skip-pr` flag | `--skip-ci` |
| `hal analyze --output` | `hal analyze --format` |
| `hal review against` | `hal review --base` |

### Migration Logic

Add to `hal cleanup`:
- If `auto-prd.json` exists and `prd.json` doesn't → rename
- If both exist → warn, keep prd.json
- Add `auto-prd.json` to orphaned files list

Add to `hal auto`:
- If `auto-state.json` has `step: "explode"` → map to `step: "convert"`
- If `auto-state.json` has `step: "pr"` → map to `step: "ci"`
- If `auto-state.json` has `step: "loop"` → map to `step: "run"`

---

## 13. Build Order

### Phase 1: `hal ci` (the missing tooth)
```
internal/ci/          ← Core logic (GitHub API, push, status, fix, merge)
cmd/ci*.go            ← CLI commands with --json contracts
```
**Unblocks:** Manual workflow completion. Skill development. Auto pipeline CI step.

### Phase 2: Convert unification + `hal auto` redesign
```
internal/skills/hal/  ← Merge explode skill into convert skill
internal/prd/         ← Add --granular mode to convert
cmd/convert.go        ← Wire --granular flag
cmd/auto.go           ← Add --compound flag, --from-prd default
internal/compound/    ← New pipeline steps (convert, validate, review, ci, archive)
```
**Unblocks:** Unified pipeline. Remove auto-prd.json. Deprecate explode.

### Phase 3: Developer skill
```
.pi/skills/factory/SKILL.md    ← Teaches agents to drive hal
```
**Unblocks:** Any coding agent can use hal end-to-end today.

### Phase 4: `hal serve` + Web
```
cmd/serve.go           ← HTTP server command
internal/api/          ← REST + WebSocket handlers
internal/factory/      ← FactoryAgent state machine
web/                   ← Next.js frontend (spec editor, kanban, pipeline)
```
**Unblocks:** The product. PM paste spec → hal builds it → approve → ship.

---

## 14. Open Design Questions

| Question | Current answer |
|---|---|
| Should `hal auto` default require confirmation before starting? | No — if you typed `hal auto`, you want it to run. The gate is typing the command. |
| Should `hal ci fix` support non-GitHub forges? | Start with GitHub only. GitLab/Bitbucket later via provider interface in `internal/ci/`. |
| Should `hal auto --compound` auto-archive before starting? | Yes — archive existing state before branching for new work. |
| What if `hal validate` fails 3 times in auto? | Abort the pipeline. Save state so `--resume` can retry after human fixes the markdown. |
| Should `hal ci` work without a prd.json? | Yes — `hal ci push` should work on any branch. It just won't auto-generate a PR body from prd.json if it's missing. |
| Where does `hal report` run — before or after CI? | Before CI push. Report needs the feature branch context (diff, commits). PR body includes the report summary. |
