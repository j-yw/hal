# PRD: Compound Engineering Integration

## Introduction

Port compound-product shell automation into goralph as native Go commands, enabling overnight autonomous loops that analyze reports, create PRDs, explode into granular tasks, run the loop, and create PRs.

This integration adds three new commands (`goralph analyze`, `goralph explode`, `goralph auto`) and supporting infrastructure to enable fully autonomous multi-step workflows. The system reads external reports (analytics, error tracking, customer feedback), picks the highest priority item, generates a PRD using a non-interactive autospec skill, explodes it into 8-15 granular tasks, executes the existing loop, and creates a draft PR for human review.

Key design decisions:
- **Single source of truth:** All files in `.goralph/`
- **Single config:** `.goralph/config.yaml` for all settings
- **Existing engine:** Use `engine.Prompt()` for analyze (already exists)
- **External agent-browser:** Not bundled - agent calls it via shell when needed
- **Skills via prompt:** Prompt instructs LLM to load skills (existing mechanism)
- **Resume capability:** Track pipeline state in `.goralph/auto-state.json`
- **Tasks format:** Always use `T-XXX` IDs (new compound style only)

## Goals

- Enable fully autonomous overnight execution from report analysis to PR creation
- Support flexible report formats (markdown, JSON, text) for integration with any external system
- Provide resume capability to continue interrupted pipelines
- Create draft PRs requiring human review before merge
- Maintain backward compatibility with existing `goralph run` workflow
- Support retry-on-failure with configurable retry count before stopping with partial progress

## User Stories

### T-001: Create compound types package
**Description:** As a developer, I need type definitions for the compound pipeline so that all components share consistent data structures.

**Acceptance Criteria:**
- [ ] Create `internal/compound/types.go` with `AnalysisResult` struct containing: `PriorityItem`, `Description`, `Rationale`, `AcceptanceCriteria []string`, `EstimatedTasks int`, `BranchName string`
- [ ] Create `PipelineState` struct with: `Step string`, `BranchName string`, `ReportPath string`, `PRDPath string`, `StartedAt time.Time`, `Analysis *AnalysisResult`
- [ ] Step field supports values: `analyze`, `branch`, `prd`, `explode`, `loop`, `pr`
- [ ] All structs have proper JSON tags for serialization
- [ ] Typecheck passes (`go vet ./...`)

### T-002: Create compound config loader
**Description:** As a developer, I need to load auto settings from config.yaml so that the pipeline behavior can be customized.

**Acceptance Criteria:**
- [ ] Create `internal/compound/config.go` with `AutoConfig` struct
- [ ] AutoConfig contains: `ReportsDir string`, `BranchPrefix string`, `QualityChecks []string`, `MaxIterations int`
- [ ] Implement `LoadConfig(dir string) (*AutoConfig, error)` that reads from `.goralph/config.yaml`
- [ ] Provide sensible defaults when config is missing: `reportsDir: .goralph/reports`, `branchPrefix: compound/`, `maxIterations: 25`
- [ ] Typecheck passes

### T-003: Create default config.yaml template
**Description:** As a developer, I need a default config template so that `goralph init` can install it.

**Acceptance Criteria:**
- [ ] Create `internal/template/config.yaml` with all settings documented via comments
- [ ] Include engine, maxIterations, retryDelay, maxRetries settings
- [ ] Include auto section with reportsDir, branchPrefix, qualityChecks, maxIterations
- [ ] Embed config.yaml in `internal/template/template.go` using `//go:embed`
- [ ] Add config.yaml to `DefaultFiles()` map
- [ ] Typecheck passes

### T-004: Update init command to install config.yaml
**Description:** As a user, I want `goralph init` to create a config.yaml file so that I can customize settings.

**Acceptance Criteria:**
- [ ] `goralph init` creates `.goralph/config.yaml` if it doesn't exist
- [ ] `goralph init` creates `.goralph/reports/` directory with `.gitkeep`
- [ ] Existing config.yaml files are preserved (not overwritten)
- [ ] Init output lists config.yaml in created files
- [ ] Typecheck passes

### T-005: Create autospec skill for non-interactive PRD generation
**Description:** As a developer, I need a skill that generates PRDs without user interaction so that the auto pipeline can create PRDs autonomously.

**Acceptance Criteria:**
- [ ] Create `internal/skills/autospec/SKILL.md` with complete PRD generation instructions
- [ ] Skill self-clarifies by using context from the analysis result (no user questions)
- [ ] Outputs PRD to `.goralph/prd-[feature].md`
- [ ] Uses `T-XXX` IDs for tasks (not `US-XXX`)
- [ ] Includes clear acceptance criteria patterns suitable for autonomous verification
- [ ] Typecheck passes (embed.go updated)

### T-006: Create explode skill for task breakdown
**Description:** As a developer, I need a skill that explodes a PRD into 8-15 granular tasks so that each task can be completed in one focused iteration.

**Acceptance Criteria:**
- [ ] Create `internal/skills/explode/SKILL.md` with task explosion instructions
- [ ] Generates 8-15 tasks from a PRD
- [ ] Tasks use boolean acceptance criteria patterns (verifiable true/false)
- [ ] Ordering: investigation → schema → backend → UI → verification
- [ ] Outputs to `.goralph/prd.json` in tasks format
- [ ] Typecheck passes (embed.go updated)

### T-007: Update skills embed.go with new skills
**Description:** As a developer, I need the new skills embedded so they can be installed by `goralph init`.

**Acceptance Criteria:**
- [ ] Add `//go:embed autospec/SKILL.md` and `//go:embed explode/SKILL.md`
- [ ] Add `autospec` and `explode` to `SkillContent` map
- [ ] Add `autospec` and `explode` to `SkillNames` slice
- [ ] Typecheck passes
- [ ] `go test ./internal/skills/...` passes

### T-008: Add Tasks field to PRD struct for dual-format support
**Description:** As a developer, I need the PRD struct to support both userStories and tasks formats so that compound mode can use the new T-XXX format while maintaining backward compatibility.

**Acceptance Criteria:**
- [ ] Add `Tasks []UserStory` field to PRD struct in `internal/engine/prd.go` with `json:"tasks,omitempty"` tag
- [ ] Update `CurrentStory()` to check `UserStories` first, then `Tasks` (backward compatible)
- [ ] Update `Progress()` to count both `UserStories` and `Tasks`
- [ ] Existing tests pass with `userStories` format
- [ ] New tests pass with `tasks` format
- [ ] Typecheck passes

### T-009: Create report finder and analyzer
**Description:** As a developer, I need functions to find and analyze reports so that the pipeline can identify the highest priority item.

**Acceptance Criteria:**
- [ ] Create `internal/compound/analyze.go` with `FindLatestReport(reportsDir string) (string, error)`
- [ ] FindLatestReport returns most recently modified file in reports dir
- [ ] Implement `FindRecentPRDs(dir string, days int) ([]string, error)` to find PRDs created in last N days
- [ ] Implement `AnalyzeReport(ctx, eng, reportPath, recentPRDs) (*AnalysisResult, error)`
- [ ] AnalyzeReport uses engine.Prompt() with constraint prompt, parses JSON response
- [ ] Returns error if report is empty or parsing fails
- [ ] Typecheck passes

### T-010: Create analyze command
**Description:** As a user, I want to run `goralph analyze` to identify the highest priority item from a report.

**Acceptance Criteria:**
- [ ] Create `cmd/analyze.go` with Cobra command
- [ ] Accepts optional `[report-path]` positional argument
- [ ] `--reports-dir` flag overrides config
- [ ] `--output` flag supports `text` (default) and `json` formats
- [ ] Shows priority item, description, rationale, estimated tasks, suggested branch name
- [ ] Exits cleanly with informational message when no reports found
- [ ] Typecheck passes

### T-011: Create git helper functions
**Description:** As a developer, I need git helper functions so that the pipeline can manage branches and PRs.

**Acceptance Criteria:**
- [ ] Create `internal/compound/git.go` with `CreateBranch(branchName string) error`
- [ ] CreateBranch creates and checks out new branch from current HEAD
- [ ] Implement `CurrentBranch() (string, error)` to return current branch name
- [ ] Implement `PushBranch(branchName string) error` to push with -u flag
- [ ] Implement `CreatePR(title, body, base string) (string, error)` using `gh pr create --draft`
- [ ] All functions handle errors gracefully with descriptive messages
- [ ] Typecheck passes

### T-012: Create explode command
**Description:** As a user, I want to run `goralph explode` to break a PRD into granular tasks.

**Acceptance Criteria:**
- [ ] Create `cmd/explode.go` with Cobra command
- [ ] Accepts `[prd-path]` positional argument (required)
- [ ] `--branch` flag sets branch name in output prd.json
- [ ] Uses engine.StreamPrompt() with explode skill prompt
- [ ] Outputs to `.goralph/prd.json`
- [ ] Shows progress with display.ShowCommandHeader and ShowCommandSuccess
- [ ] Typecheck passes

### T-013: Create pipeline state management
**Description:** As a developer, I need state management so that the pipeline can resume from interruptions.

**Acceptance Criteria:**
- [ ] Create `internal/compound/pipeline.go` with `Pipeline` struct
- [ ] Pipeline contains: `config *AutoConfig`, `engine engine.Engine`, `display *engine.Display`, `dir string`
- [ ] Implement `loadState() *PipelineState` that reads from `.goralph/auto-state.json`
- [ ] Implement `saveState(state *PipelineState) error` that writes state atomically
- [ ] Implement `clearState() error` that removes state file on completion
- [ ] State file includes all fields needed to resume any step
- [ ] Typecheck passes

### T-014: Implement pipeline Run method - analyze and branch steps
**Description:** As a developer, I need the first part of the pipeline so that reports can be analyzed and branches created.

**Acceptance Criteria:**
- [ ] Implement `(p *Pipeline) Run(ctx context.Context, opts RunOptions) error`
- [ ] RunOptions contains: `Resume bool`, `DryRun bool`, `SkipPR bool`, `ReportPath string`
- [ ] Step "analyze": Find latest report, call AnalyzeReport, save result to state
- [ ] Step "branch": Create and checkout branch using git helpers
- [ ] State is saved after each step completes
- [ ] DryRun mode shows what would happen without executing
- [ ] Typecheck passes

### T-015: Implement pipeline Run method - prd and explode steps
**Description:** As a developer, I need the PRD generation and explosion steps so that tasks can be created from the analysis.

**Acceptance Criteria:**
- [ ] Step "prd": Run engine with autospec skill prompt, passing analysis context
- [ ] Step "explode": Run engine with explode skill prompt, generates prd.json
- [ ] Both steps use engine.StreamPrompt() for visual feedback
- [ ] PRD path is saved to state after creation
- [ ] State transitions correctly: prd → explode → loop
- [ ] Typecheck passes

### T-016: Implement pipeline Run method - loop and pr steps
**Description:** As a developer, I need the execution and PR creation steps so that the pipeline completes the full cycle.

**Acceptance Criteria:**
- [ ] Step "loop": Create loop.Runner with config, call runner.Run(ctx)
- [ ] Loop uses maxIterations from auto config
- [ ] Retry failed tasks N times per config, then stop with partial progress
- [ ] Step "pr": Push branch and create draft PR using git helpers
- [ ] PR body includes summary from analysis and task completion status
- [ ] State is cleared on successful completion
- [ ] Typecheck passes

### T-017: Create auto command
**Description:** As a user, I want to run `goralph auto` to execute the full compound pipeline.

**Acceptance Criteria:**
- [ ] Create `cmd/auto.go` with Cobra command
- [ ] `--dry-run` flag shows steps without executing
- [ ] `--resume` flag continues from last state
- [ ] `--skip-pr` flag skips PR creation at end
- [ ] `--report` flag specifies report file (skips find latest)
- [ ] Shows progress for each pipeline step with display methods
- [ ] Returns PR URL on success
- [ ] Typecheck passes

### T-018: Handle empty reports gracefully
**Description:** As a user, I want the auto command to exit cleanly when there are no reports to process.

**Acceptance Criteria:**
- [ ] `goralph auto` checks for reports before starting pipeline
- [ ] If no reports found, displays informational message and exits with code 0
- [ ] Message explains where to place reports (`.goralph/reports/`)
- [ ] `goralph analyze` behaves the same way
- [ ] Typecheck passes

### T-019: Add integration tests for pipeline
**Description:** As a developer, I need integration tests so that the pipeline behavior is verified.

**Acceptance Criteria:**
- [ ] Create `internal/compound/pipeline_test.go` with integration tests
- [ ] Test state persistence across resume
- [ ] Test dry-run mode produces correct output
- [ ] Test graceful handling of missing reports
- [ ] Tests are tagged `integration` and skip when Claude CLI unavailable
- [ ] `go test -tags=integration ./internal/compound/...` passes

### T-020: Verify backward compatibility
**Description:** As a developer, I need to ensure existing workflows still work after these changes.

**Acceptance Criteria:**
- [ ] `goralph init` still creates prompt.md, progress.txt, and skills
- [ ] `goralph plan "feature"` still works (interactive mode)
- [ ] `goralph convert` still works with userStories format
- [ ] `goralph run` still works with userStories format
- [ ] `goralph run` works with new tasks format
- [ ] All existing tests pass: `make test`
- [ ] Typecheck passes: `make vet`

## Functional Requirements

- FR-1: The system must load auto configuration from `.goralph/config.yaml`
- FR-2: The system must find the most recently modified report in the configured reports directory
- FR-3: The system must analyze reports in any format (markdown, JSON, text) using the LLM
- FR-4: The system must generate a single priority item with branch name from report analysis
- FR-5: The system must create and checkout git branches using shell commands
- FR-6: The system must generate PRDs using the autospec skill without user interaction
- FR-7: The system must explode PRDs into 8-15 granular tasks using the explode skill
- FR-8: The system must persist pipeline state to `.goralph/auto-state.json` after each step
- FR-9: The system must resume from the last completed step when `--resume` is passed
- FR-10: The system must create draft PRs using `gh pr create --draft`
- FR-11: The system must retry failed tasks according to config, then stop with partial progress
- FR-12: The system must exit cleanly with informational message when no reports are found
- FR-13: The system must support both `userStories` and `tasks` fields in prd.json

## Non-Goals

- **Not bundling agent-browser:** The agent calls browser automation via shell when needed
- **Not generating reports:** Reports are external inputs placed by user's systems
- **Not auto-merging PRs:** All PRs are created as drafts requiring human review
- **Not supporting US-XXX format:** Compound mode always uses T-XXX task IDs
- **Not replacing interactive mode:** `goralph plan` continues to work interactively
- **Not running quality checks directly:** The LLM agent runs checks per prompt instructions

## Technical Considerations

- Reuse existing `engine.Engine` interface and `engine.Prompt()`/`engine.StreamPrompt()` methods
- Reuse existing `loop.Runner` for task execution
- State file (`.goralph/auto-state.json`) should be atomic writes to prevent corruption
- Branch names should be sanitized (lowercase, hyphens, no special chars)
- PR creation requires `gh` CLI to be installed and authenticated
- Config loading should use `gopkg.in/yaml.v3` for parsing

## Success Metrics

- Full pipeline completes from report to draft PR without human intervention
- Pipeline can resume after interruption (kill mid-run, restart with `--resume`)
- Existing `goralph run` workflow unaffected by changes
- All unit tests pass (`make test`)
- All integration tests pass (`go test -tags=integration ./...`)

## Open Questions

- Should the auto command support multiple reports in sequence (batch mode)?
- Should there be a notification mechanism when pipeline completes overnight?
