# Spec: `hal auto` Refactor

> Unify the auto pipeline so it works from PRD (default) or report (compound), merge convert + explode, kill auto-prd.json.

---

## 1. Problem Statement

Today `hal auto` only works after `hal report` — it requires a report to analyze. If a human writes a spec with `hal plan`, there's no way to say "take it from here." Additionally, `hal convert` and `hal explode` are two commands that produce the same JSON schema into different files (`prd.json` vs `auto-prd.json`), creating unnecessary complexity.

### Current State

```
hal auto: analyze report → branch → prd (autospec) → explode → loop → pr
          ^^^^^^^^^^^^^^^^                             ^^^^^^^         ^^
          only entry point                             separate cmd    no CI/review
```

- `hal auto` requires a report — can't start from a PRD
- `hal explode` writes `auto-prd.json` — separate from `prd.json`
- `hal convert` and `hal explode` produce identical JSON schema
- No validate step, no review step, no CI integration
- Pipeline jumps from loop straight to PR (no quality checks)

### Target State

```
hal auto:           discover prd-*.md → branch → convert → validate → run → review → report → ci → archive
hal auto --compound: analyze report → spec → [same as above from branch onward]
```

- Default entry: existing `prd-*.md` (human-written or provided)
- Compound entry: analyze report, generate markdown, then same flow
- One file: `prd.json` everywhere
- One convert command: `hal convert --granular` absorbs explode
- Full pipeline: validate + review + CI baked in

---

## 2. Changes Overview

### 2.1 `hal convert` — absorb `--granular`

**File changes:**
- `cmd/convert.go` — add `--granular` flag
- `internal/prd/convert.go` — pass granular mode to engine prompt
- `internal/skills/hal/SKILL.md` — merge explode skill content into convert skill
- `internal/skills/explode/` — keep for backward compat, mark deprecated in skill metadata
- `internal/skills/embed.go` — update embed list (keep explode for deprecation period)

**New flag:**
```go
convertCmd.Flags().BoolVar(&convertGranularFlag, "granular", false,
    "Decompose into 8-15 atomic tasks (T-XXX IDs) for autonomous execution")
```

**Behavior with `--granular`:**
- Uses granular section of the merged convert skill
- Enforces 8-15 tasks, T-XXX IDs, one-iteration sizing
- Writes to `prd.json` (same as standard convert) — NOT auto-prd.json
- Branch name derived from markdown filename or `--branch` flag

**Skill merge strategy:**

The current `hal` skill (`internal/skills/hal/SKILL.md`) gets a new section:

```markdown
## Granular Mode (--granular)

When granular mode is requested, decompose the PRD into 8-15 atomic tasks:

- T-XXX IDs (not US-XXX)
- Each task completable in ONE agent iteration
- 8-15 tasks enforced (fewer = too big, more = over-decomposed)
- Dependency-ordered: types → logic → integration → verification
- Boolean acceptance criteria only
- Every task ends with "Typecheck passes"

| Complexity | Target |
|---|---|
| Simple (1-2 files) | 8-10 tasks |
| Medium (3-5 files) | 10-12 tasks |
| Complex (6+ files) | 12-15 tasks |
```

**Convert prompt change (`internal/prd/convert.go`):**

```go
func buildConvertPrompt(skill, mdContent, outPath string, granular bool) string {
    mode := "standard"
    if granular {
        mode = "granular"
    }
    return fmt.Sprintf(`You are a PRD conversion agent. Follow the skill instructions below.

<skill>
%s
</skill>

<mode>%s</mode>

<prd>
%s
</prd>

Convert this PRD to JSON following the skill rules for %s mode.
Write the JSON directly to %s using the Write tool.`, skill, mode, mdContent, mode, outPath)
}
```

### 2.2 `hal explode` — deprecate

**File changes:**
- `cmd/explode.go` — wrap with deprecation warning, delegate to convert --granular

```go
func runExplode(cmd *cobra.Command, args []string) error {
    fmt.Fprintln(os.Stderr, "⚠️  hal explode is deprecated. Use: hal convert --granular "+args[0])
    // Set convert flags and delegate
    convertGranularFlag = true
    convertOutputFlag = "" // default to prd.json
    return runConvertWithDeps(cmd, args, defaultConvertDeps)
}
```

**Output path change:** The deprecated `hal explode` now writes to `prd.json` (not `auto-prd.json`). This is a breaking change for scripts that read `auto-prd.json`, but the migration window handles it.

### 2.3 Kill `auto-prd.json`

**File changes:**
- `internal/template/template.go` — remove `AutoPRDFile` constant (or keep as deprecated alias)
- `internal/compound/pipeline.go` — `runExplodeStep` → `runConvertStep`, writes to `prd.json`
- `internal/compound/pipeline.go` — `runLoopStep` config uses `template.PRDFile` (already does when not in auto)
- `cmd/cleanup.go` — add `auto-prd.json` to orphaned files list

**Migration in pipeline.go:**

```go
// runConvertStep replaces runExplodeStep
func (p *Pipeline) runConvertStep(ctx context.Context, state *PipelineState, opts RunOptions) error {
    p.display.ShowInfo("   Step: convert\n")

    // Output is always prd.json now
    outPath := filepath.Join(p.dir, template.HalDir, template.PRDFile)

    // ... same engine prompt logic but using merged convert skill with granular mode ...

    state.Step = StepValidate
    return p.saveState(state)
}
```

### 2.4 `hal auto` — two entry points

**File changes:**
- `cmd/auto.go` — new flags, new CLI interface, updated RunOptions
- `internal/compound/pipeline.go` — new step flow, new entry point logic
- `internal/compound/types.go` — updated PipelineState, new step constants

**New CLI interface:**

```go
var autoCmd = &cobra.Command{
    Use:   "auto [prd-path]",
    Short: "Run the full autonomous pipeline from PRD to merge",
    Long: `Execute the autonomous pipeline: convert → validate → run → review → report → CI → merge.

Default mode starts from an existing prd-*.md file:
  hal auto                         # Discover newest prd-*.md
  hal auto .hal/prd-auth.md        # Use specific markdown

Compound mode starts from a report (analyze → generate PRD → execute):
  hal auto --compound              # Analyze latest report first
  hal auto --compound --report r.md

The pipeline saves state after each step for --resume.`,
    Example: `  hal auto
  hal auto .hal/prd-auth.md
  hal auto --compound
  hal auto --compound --report .hal/reports/report.md
  hal auto --resume
  hal auto --skip-ci
  hal auto --base develop --json`,
    Args: maxArgsValidation(1),
    RunE: runAuto,
}
```

**New flags:**

```go
func init() {
    autoCmd.Flags().BoolVar(&autoCompoundFlag, "compound", false,
        "Start from a report (analyze → generate PRD → execute)")
    autoCmd.Flags().BoolVar(&autoSkipCIFlag, "skip-ci", false,
        "Stop after review (no push/merge)")
    autoCmd.Flags().BoolVar(&autoDryRunFlag, "dry-run", false, "Show steps without executing")
    autoCmd.Flags().BoolVar(&autoResumeFlag, "resume", false, "Continue from last saved state")
    autoCmd.Flags().StringVar(&autoReportFlag, "report", "", "Specific report file (compound mode)")
    autoCmd.Flags().StringVarP(&autoEngineFlag, "engine", "e", "codex", "Engine to use")
    autoCmd.Flags().StringVarP(&autoBaseFlag, "base", "b", "", "Base branch")
    autoCmd.Flags().BoolVar(&autoJSONFlag, "json", false, "Machine-readable output")

    // Deprecated flags
    autoCmd.Flags().BoolVar(&autoSkipPRFlag, "skip-pr", false, "Deprecated: use --skip-ci")
    autoCmd.Flags().MarkDeprecated("skip-pr", "use --skip-ci instead")
}
```

**Entry point logic in `runAuto`:**

```go
func runAuto(cmd *cobra.Command, args []string) error {
    // ...flag resolution...

    compound := autoCompoundFlag
    // --report implies --compound
    if reportPath != "" {
        compound = true
    }

    if compound {
        // Compound mode: start from report
        // Check reports exist (unless resuming)
        if !resume {
            if reportPath == "" {
                _, err := compound.FindLatestReport(config.ReportsDir)
                if err != nil {
                    return fmt.Errorf("no reports found: %w", err)
                }
            }
        }
    } else {
        // Default mode: start from PRD
        var mdPath string
        if len(args) > 0 {
            mdPath = args[0]
        }
        if !resume {
            if mdPath == "" {
                // Auto-discover newest prd-*.md
                discovered, err := prd.FindNewestMarkdown(template.HalDir)
                if err != nil {
                    return fmt.Errorf("no prd-*.md found: run 'hal plan' first or provide a path")
                }
                mdPath = discovered
            }
        }
        opts.SourceMarkdown = mdPath
    }

    opts.Compound = compound
    // ... run pipeline ...
}
```

### 2.5 Pipeline Step Changes

**`internal/compound/types.go` — new constants:**

```go
const (
    // Compound-only entry steps
    StepAnalyze  = "analyze"
    StepSpec     = "spec"

    // Common flow (default mode starts at StepBranch)
    StepBranch   = "branch"
    StepConvert  = "convert"     // was: StepExplode
    StepValidate = "validate"    // NEW
    StepRun      = "run"         // was: StepLoop
    StepReview   = "review"      // NEW
    StepReport   = "report"      // NEW
    StepCI       = "ci"          // was: StepPR
    StepArchive  = "archive"     // NEW
    StepDone     = "done"

    // Deprecated — mapped during resume
    StepExplode  = "explode"     // maps to StepConvert
    StepLoop     = "loop"        // maps to StepRun
    StepPR       = "pr"          // maps to StepCI
)
```

**`internal/compound/types.go` — updated state:**

```go
type PipelineState struct {
    Step             string          `json:"step"`
    EntryMode        string          `json:"entryMode"`            // "prd" or "compound"
    BaseBranch       string          `json:"baseBranch,omitempty"`
    BranchName       string          `json:"branchName"`
    SourceMarkdown   string          `json:"sourceMarkdown"`
    ReportPath       string          `json:"reportPath,omitempty"`
    StartedAt        time.Time       `json:"startedAt"`
    ValidateAttempts int             `json:"validateAttempts,omitempty"`
    RunIterations    int             `json:"runIterations,omitempty"`
    RunComplete      bool            `json:"runComplete,omitempty"`
    CIAttempts       int             `json:"ciAttempts,omitempty"`
    PRUrl            string          `json:"prUrl,omitempty"`
    Analysis         *AnalysisResult `json:"analysis,omitempty"`
}
```

**`internal/compound/pipeline.go` — new Run method:**

```go
func (p *Pipeline) Run(ctx context.Context, opts RunOptions) error {
    var state *PipelineState
    if opts.Resume {
        state = p.loadState()
        if state == nil {
            return fmt.Errorf("no saved state to resume from")
        }
        migrateStepNames(state) // explode→convert, loop→run, pr→ci
    } else {
        startStep := StepBranch
        entryMode := "prd"
        if opts.Compound {
            startStep = StepAnalyze
            entryMode = "compound"
        }
        state = &PipelineState{
            Step:           startStep,
            EntryMode:      entryMode,
            SourceMarkdown: opts.SourceMarkdown,
            StartedAt:      time.Now(),
        }
    }

    // ... base branch resolution ...

    for {
        select {
        case <-ctx.Done():
            p.saveState(state)
            return ctx.Err()
        default:
        }

        var err error
        switch state.Step {
        // Compound-only entry
        case StepAnalyze:
            err = p.runAnalyzeStep(ctx, state, opts)
        case StepSpec:
            err = p.runSpecStep(ctx, state, opts)

        // Common flow
        case StepBranch:
            err = p.runBranchStep(ctx, state, opts)
        case StepConvert:
            err = p.runConvertStep(ctx, state, opts)
        case StepValidate:
            err = p.runValidateStep(ctx, state, opts)
        case StepRun:
            err = p.runRunStep(ctx, state, opts)
        case StepReview:
            err = p.runReviewStep(ctx, state, opts)
        case StepReport:
            err = p.runReportStep(ctx, state, opts)
        case StepCI:
            err = p.runCIStep(ctx, state, opts)
        case StepArchive:
            err = p.runArchiveStep(ctx, state, opts)
        case StepDone:
            return nil

        // Deprecated step names (resume from old state files)
        case StepExplode:
            state.Step = StepConvert
            continue
        case StepLoop:
            state.Step = StepRun
            continue
        case StepPR:
            state.Step = StepCI
            continue

        default:
            return fmt.Errorf("unknown pipeline step: %s", state.Step)
        }

        if err != nil {
            p.saveState(state)
            return fmt.Errorf("step %s failed: %w", state.Step, err)
        }
    }
}
```

### 2.6 New Pipeline Steps (implementation sketch)

**`runSpecStep`** — compound-only, replaces current `runPRDStep`:

```go
func (p *Pipeline) runSpecStep(ctx context.Context, state *PipelineState, opts RunOptions) error {
    // Generate prd-*.md from analysis using autospec skill
    // (same as current runPRDStep)
    // Sets state.SourceMarkdown to the generated file
    state.Step = StepBranch
    return p.saveState(state)
}
```

**`runConvertStep`** — replaces `runExplodeStep`:

```go
func (p *Pipeline) runConvertStep(ctx context.Context, state *PipelineState, opts RunOptions) error {
    // Call prd.ConvertWithEngine with granular=true
    // Writes to .hal/prd.json (not auto-prd.json)
    state.Step = StepValidate
    return p.saveState(state)
}
```

**`runValidateStep`** — NEW:

```go
func (p *Pipeline) runValidateStep(ctx context.Context, state *PipelineState, opts RunOptions) error {
    result, err := prd.ValidateWithEngine(ctx, p.engine, prdPath, p.display)
    if err != nil || !result.Valid {
        state.ValidateAttempts++
        if state.ValidateAttempts >= 3 {
            return fmt.Errorf("PRD validation failed after 3 attempts")
        }
        // Re-convert with error feedback
        p.display.ShowInfo("   Validation failed (attempt %d/3), re-converting...\n", state.ValidateAttempts)
        state.Step = StepConvert  // go back to convert
        return p.saveState(state)
    }
    state.Step = StepRun
    return p.saveState(state)
}
```

**`runReviewStep`** — NEW:

```go
func (p *Pipeline) runReviewStep(ctx context.Context, state *PipelineState, opts RunOptions) error {
    // Run hal review --base <base> internally
    // Uses compound.RunCodexReviewLoop
    state.Step = StepReport
    return p.saveState(state)
}
```

**`runReportStep`** — NEW:

```go
func (p *Pipeline) runReportStep(ctx context.Context, state *PipelineState, opts RunOptions) error {
    // Run hal report internally (while on feature branch)
    // Report captures diff, commits, progress context
    state.Step = StepCI
    return p.saveState(state)
}
```

**`runCIStep`** — replaces `runPRStep`, uses `internal/ci/`:

```go
func (p *Pipeline) runCIStep(ctx context.Context, state *PipelineState, opts RunOptions) error {
    if opts.SkipCI {
        state.Step = StepArchive
        return p.saveState(state)
    }

    // 1. Push branch
    if err := ci.Push(ctx, ci.PushOpts{...}); err != nil { return err }

    // 2. Create draft PR
    pr, err := ci.CreatePR(ctx, ci.PROpts{...})
    state.PRUrl = pr.URL

    // 3. Wait for CI
    result, err := ci.WaitForChecks(ctx, ci.WaitOpts{Timeout: 30*time.Minute})
    if err != nil { return err }

    // 4. Fix loop if needed
    for result.Status == ci.StatusFailing && state.CIAttempts < 3 {
        state.CIAttempts++
        if err := ci.FixFailures(ctx, p.engine, result, p.display); err != nil { return err }
        // Re-check
        result, err = ci.WaitForChecks(ctx, ci.WaitOpts{Timeout: 30*time.Minute})
        if err != nil { return err }
    }
    if result.Status != ci.StatusPassing {
        return fmt.Errorf("CI still failing after %d fix attempts", state.CIAttempts)
    }

    // 5. Merge
    if err := ci.Merge(ctx, ci.MergeOpts{Strategy: "squash"}); err != nil { return err }

    state.Step = StepArchive
    return p.saveState(state)
}
```

**`runArchiveStep`** — NEW:

```go
func (p *Pipeline) runArchiveStep(ctx context.Context, state *PipelineState, opts RunOptions) error {
    // Archive completed feature state
    archive.Create(halDir, featureName, io.Discard)
    // Clear pipeline state
    p.clearState()
    state.Step = StepDone
    return nil
}
```

### 2.7 Updated `RunOptions`

```go
type RunOptions struct {
    Resume         bool
    DryRun         bool
    Compound       bool     // compound mode (from report)
    SkipCI         bool     // stop after review
    ReportPath     string   // compound mode: specific report
    SourceMarkdown string   // default mode: specific prd-*.md
    BaseBranch     string
}
```

---

## 3. Updated `AutoResult` JSON Contract

```json
{
  "contractVersion": 2,
  "ok": true,
  "entryMode": "prd",
  "resumed": false,
  "duration": "12m30s",
  "steps": {
    "branch": {"status": "completed", "branch": "hal/user-auth"},
    "convert": {"status": "completed", "tasks": 12},
    "validate": {"status": "completed", "attempts": 1},
    "run": {"status": "completed", "iterations": 8, "complete": true},
    "review": {"status": "completed", "issuesFound": 3, "fixesApplied": 2},
    "report": {"status": "completed", "path": ".hal/reports/report-2026-03-25.md"},
    "ci": {"status": "completed", "prUrl": "https://github.com/org/repo/pull/42", "ciAttempts": 0}
  },
  "summary": "Auto pipeline completed. 12 tasks built, reviewed, CI green, PR merged.",
  "nextAction": {
    "id": "run_compound",
    "command": "hal auto --compound",
    "description": "Use the report to start the next feature."
  }
}
```

---

## 4. Migration

### State file migration

When loading `auto-state.json` for `--resume`:

```go
func migrateStepNames(state *PipelineState) {
    switch state.Step {
    case "explode":
        state.Step = StepConvert
    case "loop":
        state.Step = StepRun
    case "pr":
        state.Step = StepCI
    }
    // Default entryMode for old state files
    if state.EntryMode == "" {
        state.EntryMode = "compound" // old states were always compound
    }
}
```

### File migration

Add to `hal cleanup` orphaned files:
```go
var orphanedFiles = []string{
    "auto-prd.json",
    // ... existing entries
}
```

Add to `hal auto` startup:
```go
// Migrate auto-prd.json → prd.json if needed
autoPRD := filepath.Join(halDir, "auto-prd.json")
prdJSON := filepath.Join(halDir, "prd.json")
if _, err := os.Stat(autoPRD); err == nil {
    if _, err := os.Stat(prdJSON); os.IsNotExist(err) {
        os.Rename(autoPRD, prdJSON)
    }
}
```

### Flag deprecation

`--skip-pr` → prints warning, maps to `SkipCI`:
```go
if autoSkipPRFlag {
    fmt.Fprintln(os.Stderr, "⚠️  --skip-pr is deprecated, use --skip-ci")
    opts.SkipCI = true
}
```

### Status integration

Update `internal/status/status.go`:
- `compound_complete` next action: `hal report` → `hal auto --compound`
- `manual_complete` next action: add `hal auto` as alternative to `hal report`
- Add new state: `auto_active` (when `entryMode` is `prd` in state file)

---

## 5. Dependency on `hal ci`

The `StepCI` implementation requires `internal/ci/` to exist. Build order:

1. **Phase A:** `hal convert --granular` + explode deprecation + kill auto-prd.json
2. **Phase B:** `hal auto` refactor with new entry points + new steps (validate, review, report)
3. **Phase C:** `StepCI` integration (requires `hal ci` spec to be implemented first)

Phase A and B can ship with `--skip-ci` as default until `hal ci` lands. The pipeline stops at StepReport and the user manually pushes.

---

## 6. Test Plan

### Unit tests

| Test | File | Validates |
|---|---|---|
| Convert with `--granular` flag | `cmd/convert_test.go` | Flag wiring, output path is prd.json |
| Explode deprecation warning | `cmd/explode_test.go` | Warning printed, delegates to convert |
| Pipeline step migration | `internal/compound/pipeline_test.go` | `explode→convert`, `loop→run`, `pr→ci` |
| Default entry discovers prd-*.md | `cmd/auto_test.go` | Newest by mtime selected |
| Compound entry requires report | `cmd/auto_test.go` | Error when no reports found |
| `--report` implies `--compound` | `cmd/auto_test.go` | Flag inference |
| Validate retry loop (max 3) | `internal/compound/pipeline_test.go` | Re-convert on failure, abort at 3 |
| State resume with entryMode | `internal/compound/pipeline_test.go` | Both prd and compound resume correctly |
| auto-prd.json migration | `internal/compound/pipeline_test.go` | Renamed to prd.json on startup |

### Integration tests

| Test | Validates |
|---|---|
| `hal auto prd-*.md --dry-run` | Full pipeline preview from PRD entry |
| `hal auto --compound --dry-run` | Full pipeline preview from report entry |
| `hal convert --granular prd.md` | Produces prd.json with T-XXX IDs, 8-15 tasks |
| `hal explode prd.md` | Deprecation warning + writes to prd.json (not auto-prd.json) |
