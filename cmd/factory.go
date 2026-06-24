package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

const (
	FactoryRunContractVersion    = "factory-run-v1"
	FactoryListContractVersion   = "factory-list-v1"
	FactoryStatusContractVersion = "factory-status-v1"
)

var factoryListJSONFlag bool
var factoryStatusJSONFlag bool
var factoryRunReportFlag string
var factoryRunBaseFlag string
var factoryRunJSONFlag bool
var factoryRunSandboxFlag bool

var factoryCmd = &cobra.Command{
	Use:   "factory",
	Short: "Run and inspect factory workflows",
	Long: `Run local factory workflows and inspect durable factory run history stored
under Hal's global config directory.

Factory run wraps the local auto pipeline while list and status read the global factory store,
which is separate from per-project .hal runtime state.`,
	Example: `  hal factory run .hal/prd-feature.md
  hal factory run --report .hal/reports/analysis.md --json
  hal factory list
  hal factory list --json
  hal factory status <run-id> --json`,
}

var factoryRunCmd = &cobra.Command{
	Use:   "run [prd-path]",
	Short: "Run a factory executor",
	Args:  validateFactoryRunArgs,
	Long: `Run the local factory executor by wrapping the existing hal auto compound
pipeline, or pass --sandbox to run the factory executor in a managed sandbox.

Provide at most one positional PRD markdown path to start from an existing
spec, or use --report <path> to start from an analysis report. The positional
path and --report are mutually exclusive. Use --base <branch> to pass a target
base branch to the executor. Sandbox mode requires --base so the remote
workspace can be checked out deterministically. Use --sandbox for remote
sandbox-backed execution, and --json for machine-readable factory-run-v1 output.`,
	Example: `  hal factory run .hal/prd-feature.md
  hal factory run --report .hal/reports/analysis.md
  hal factory run .hal/prd-feature.md --base main --json
  hal factory run .hal/prd-feature.md --sandbox --base main`,
	RunE: runFactoryRun,
}

var factoryListCmd = &cobra.Command{
	Use:   "list",
	Short: "List stored factory runs",
	Args:  noArgsValidation(),
	Long: `List stored factory runs from the global factory store.

The default output is a compact table of run IDs, statuses, branches, steps,
and update timestamps. Use --json for machine-readable output following the
factory-list-v1 contract. JSON output includes run summaries only; event
timelines are intentionally omitted from the list surface.`,
	Example: `  hal factory list
  hal factory list --json`,
	RunE: runFactoryList,
}

var factoryStatusCmd = &cobra.Command{
	Use:   "status <run-id>",
	Short: "Inspect a stored factory run",
	Args:  exactArgsValidation(1),
	Long: `Inspect one stored factory run from the global factory store.

The default output is a compact table with run metadata and timeline entries.
Use --json for machine-readable output following the factory-status-v1 contract.
JSON output includes the full run record and timeline events in append order.`,
	Example: `  hal factory status run-20260620-001
  hal factory status run-20260620-001 --json`,
	RunE: runFactoryStatus,
}

func init() {
	factoryRunCmd.Flags().StringVar(&factoryRunReportFlag, "report", "", "Start from an analysis report path")
	factoryRunCmd.Flags().StringVar(&factoryRunBaseFlag, "base", "", "Target base branch for follow-up review or CI")
	factoryRunCmd.Flags().BoolVar(&factoryRunSandboxFlag, "sandbox", false, "Run the factory executor in a managed sandbox")
	factoryRunCmd.Flags().BoolVar(&factoryRunJSONFlag, "json", false, "Output machine-readable JSON (factory-run-v1 contract)")
	factoryListCmd.Flags().BoolVar(&factoryListJSONFlag, "json", false, "Output machine-readable JSON (factory-list-v1 contract)")
	factoryStatusCmd.Flags().BoolVar(&factoryStatusJSONFlag, "json", false, "Output machine-readable JSON (factory-status-v1 contract)")
	factoryCmd.AddCommand(factoryRunCmd)
	factoryCmd.AddCommand(factoryListCmd)
	factoryCmd.AddCommand(factoryStatusCmd)
	rootCmd.AddCommand(factoryCmd)
}

type factoryListDeps struct {
	defaultStore func() (factory.Store, error)
}

var defaultFactoryListDeps = factoryListDeps{
	defaultStore: factory.DefaultStore,
}

type factoryStatusDeps struct {
	defaultStore func() (factory.Store, error)
}

var defaultFactoryStatusDeps = factoryStatusDeps{
	defaultStore: factory.DefaultStore,
}

type factoryRunDeps struct {
	defaultStore  func() (factory.Store, error)
	newRunID      func() (string, error)
	now           func() time.Time
	workingDir    func() (string, error)
	currentBranch func(string) (string, error)
	repoRemote    func(string) (string, error)
	runPipeline   func(context.Context, factoryRunPipelineRequest) error
	runSandbox    func(context.Context, factorySandboxExecutorRequest) error
}

type factoryRunPipelineRequest struct {
	RunID          string
	Request        factoryRunRequest
	Record         factory.RunRecord
	Store          factory.Store
	RecordProgress func(factoryRunProgressEvent) error
}

var defaultFactoryRunDeps = factoryRunDeps{
	defaultStore:  factory.DefaultStore,
	newRunID:      sandbox.NewV7,
	now:           time.Now,
	workingDir:    os.Getwd,
	currentBranch: compound.CurrentBranchOptionalInDir,
	repoRemote:    readGitRemoteOptionalInDir,
	runPipeline:   runFactoryRunPipeline,
	runSandbox: func(ctx context.Context, req factorySandboxExecutorRequest) error {
		return runFactorySandboxExecutorWithDeps(ctx, req, defaultFactorySandboxExecutorDeps)
	},
}

type factoryRunRequest struct {
	MarkdownPath string
	ReportPath   string
	BaseBranch   string
	Sandbox      bool
	JSON         bool
}

type factoryRunAutoRequest struct {
	Args           []string
	ReportPath     string
	BaseBranch     string
	RecordProgress func(factoryRunProgressEvent) error
}

type factoryRunProgressEvent struct {
	Message  string
	Summary  string
	Metadata map[string]any
}

type factoryTimelineEvent struct {
	EventType string
	Message   string
	Summary   string
	Metadata  map[string]any
}

type factoryRunPipelineDeps struct {
	runAuto func(context.Context, factoryRunAutoRequest) error
}

// FactoryListResponse is the machine-readable JSON output for hal factory list --json.
type FactoryListResponse struct {
	ContractVersion string              `json:"contractVersion"`
	Runs            []FactoryRunSummary `json:"runs"`
}

// FactoryStatusResponse is the machine-readable JSON output for hal factory status --json.
type FactoryStatusResponse struct {
	ContractVersion string                `json:"contractVersion"`
	Run             factory.RunRecord     `json:"run"`
	Timeline        []factory.EventRecord `json:"timeline"`
}

// FactoryRunSummary is the list surface for one factory run. It intentionally
// excludes full artifact records and event timelines so list output stays small.
type FactoryRunSummary struct {
	RunID         string                  `json:"runId"`
	Status        string                  `json:"status"`
	Source        factory.SourceMetadata  `json:"source"`
	RepoPath      string                  `json:"repoPath"`
	RepoRemote    string                  `json:"repoRemote"`
	BranchName    string                  `json:"branchName"`
	BaseBranch    string                  `json:"baseBranch"`
	SandboxName   string                  `json:"sandboxName,omitempty"`
	CurrentStep   string                  `json:"currentStep"`
	CreatedAt     time.Time               `json:"createdAt"`
	UpdatedAt     time.Time               `json:"updatedAt"`
	FinishedAt    *time.Time              `json:"finishedAt,omitempty"`
	ArtifactCount int                     `json:"artifactCount"`
	Failure       *factory.FailureSummary `json:"failure,omitempty"`
}

func validateFactoryRunArgs(cmd *cobra.Command, args []string) error {
	reportPath := ""
	if cmd != nil && cmd.Flags().Lookup("report") != nil {
		value, err := cmd.Flags().GetString("report")
		if err != nil {
			return err
		}
		reportPath = value
	}

	if _, err := parseFactoryRunRequest(args, reportPath, "", false, false); err != nil {
		return factoryRunArgsValidationError(cmd, err)
	}
	return nil
}

func factoryRunArgsValidationError(cmd *cobra.Command, err error) error {
	if factoryRunJSONRequested(cmd) {
		out := io.Writer(os.Stdout)
		if cmd != nil {
			out = cmd.OutOrStdout()
		}
		if renderErr := renderFactoryRunValidationErrorJSON(out, err); renderErr != nil {
			return renderErr
		}
		return exitWithCode(cmd, ExitCodeValidation, nil)
	}
	return exitWithCode(cmd, ExitCodeValidation, err)
}

func runFactoryRun(cmd *cobra.Command, args []string) error {
	req, err := factoryRunRequestFromCommand(cmd, args)
	if err != nil {
		if factoryRunJSONRequested(cmd) {
			out := io.Writer(os.Stdout)
			if cmd != nil {
				out = cmd.OutOrStdout()
			}
			if renderErr := renderFactoryRunValidationErrorJSON(out, err); renderErr != nil {
				return renderErr
			}
			return &ExitCodeError{Code: factoryRenderedJSONExitCode(err)}
		}
		return err
	}

	ctx := context.Background()
	out := io.Writer(os.Stdout)
	if cmd != nil {
		if cmd.Context() != nil {
			ctx = cmd.Context()
		}
		out = cmd.OutOrStdout()
	}

	countingOut := newFactoryCountingWriter(out)
	err = runFactoryRunWithDeps(ctx, ".", req, countingOut, defaultFactoryRunDeps)
	return suppressFactoryJSONRenderedError(err, req.JSON, countingOut)
}

func factoryRunJSONRequested(cmd *cobra.Command) bool {
	if cmd == nil || cmd.Flags().Lookup("json") == nil {
		return false
	}
	value, err := cmd.Flags().GetBool("json")
	return err == nil && value
}

func runFactoryRunWithDeps(ctx context.Context, dir string, req factoryRunRequest, out io.Writer, deps factoryRunDeps) error {
	if out == nil {
		out = io.Discard
	}
	deps = normalizeFactoryRunDeps(deps)
	if deps.defaultStore == nil {
		return fmt.Errorf("factory store dependency is required")
	}
	if deps.runPipeline == nil {
		return fmt.Errorf("factory run pipeline dependency is required")
	}
	if deps.runSandbox == nil {
		return fmt.Errorf("factory sandbox executor dependency is required")
	}

	store, err := deps.defaultStore()
	if err != nil {
		return fmt.Errorf("open factory store: %w", err)
	}
	record, bootstrapRepositoryURL, err := newFactoryRunRecord(dir, req, deps)
	if err != nil {
		return err
	}
	if err := createFactoryRunRecord(store, record); err != nil {
		return err
	}
	if err := recordFactoryRunStarted(store, record); err != nil {
		return err
	}

	runningRecord, err := markFactoryRunInProgress(store, record, deps.now())
	if err != nil {
		return err
	}
	if err := recordFactoryRunPipelineStarted(store, runningRecord); err != nil {
		return err
	}

	pipelineReq := factoryRunPipelineRequest{
		RunID:   runningRecord.RunID,
		Request: req,
		Record:  runningRecord,
		Store:   store,
		RecordProgress: func(event factoryRunProgressEvent) error {
			return recordFactoryRunProgress(store, runningRecord.RunID, deps.now(), event)
		},
	}
	artifactSnapshot := snapshotFactoryRunArtifacts(dir)
	runErr := error(nil)
	if req.Sandbox {
		remoteOutput := out
		if req.JSON {
			remoteOutput = io.Discard
		}
		runErr = deps.runSandbox(ctx, factorySandboxExecutorRequest{
			ProjectDir:             dir,
			BootstrapRepositoryURL: bootstrapRepositoryURL,
			RunRecord:              runningRecord,
			RemoteAuto:             factoryRunAutoRequestFromFactoryRequest(req),
			RemoteOutput:           remoteOutput,
		})
	} else {
		runErr = deps.runPipeline(ctx, pipelineReq)
	}
	if runErr != nil {
		failedAt := deps.now()
		failedRecord := runningRecord
		var recordErrs []error
		if refreshedRecord, branchErr := refreshFactoryRunBranchForMode(store, runningRecord.RunID, dir, req, deps, failedAt); branchErr != nil {
			recordErrs = append(recordErrs, branchErr)
		} else {
			failedRecord = refreshedRecord
		}
		if artifactRecord, artifactErr := recordFactoryRunArtifacts(store, runningRecord.RunID, dir, req, artifactSnapshot, failedAt); artifactErr != nil {
			recordErrs = append(recordErrs, fmt.Errorf("record factory artifacts: %w", artifactErr))
		} else {
			failedRecord = artifactRecord
		}

		recordErr := runErr
		if req.Sandbox {
			recordErr = factorySandboxPipelineRecordError(failedRecord, runErr)
		}
		failedRecord, failureErr := markFactoryRunFailed(store, failedRecord, failedAt, recordErr)
		if failureErr != nil {
			recordErrs = append(recordErrs, failureErr)
		}
		if eventErr := recordFactoryRunPipelineFailed(store, runningRecord.RunID, failedAt, recordErr); eventErr != nil {
			recordErrs = append(recordErrs, fmt.Errorf("record factory failure event: %w", eventErr))
		}
		skipFailureClassification := false
		if req.Sandbox {
			classified, classifyErr := factoryRunHasFailureClassificationEvent(store, failedRecord.RunID)
			if classifyErr != nil {
				recordErrs = append(recordErrs, fmt.Errorf("inspect factory failure classification events: %w", classifyErr))
				skipFailureClassification = true
			} else {
				skipFailureClassification = classified
			}
		}
		if failedRecord.Failure != nil && !skipFailureClassification {
			if eventErr := recordFactoryRunFailureClassified(store, failedRecord.RunID, failedAt, *failedRecord.Failure); eventErr != nil {
				recordErrs = append(recordErrs, fmt.Errorf("record factory failure classification event: %w", eventErr))
			}
		}
		if len(recordErrs) > 0 {
			return errors.Join(append([]error{runErr}, recordErrs...)...)
		}
		if renderErr := renderFactoryRunResult(out, store, failedRecord.RunID, req.JSON); renderErr != nil {
			return errors.Join(runErr, renderErr)
		}
		return runErr
	}

	completedAt := deps.now()
	if _, err := refreshFactoryRunBranchForMode(store, runningRecord.RunID, dir, req, deps, completedAt); err != nil {
		return err
	}
	completedRecord, err := recordFactoryRunArtifacts(store, runningRecord.RunID, dir, req, artifactSnapshot, completedAt)
	if err != nil {
		return err
	}
	completedRecord, err = markFactoryRunSucceeded(store, completedRecord, completedAt)
	if err != nil {
		return err
	}
	if err := recordFactoryRunPipelineSucceeded(store, completedRecord.RunID, completedAt); err != nil {
		return err
	}
	return renderFactoryRunResult(out, store, completedRecord.RunID, req.JSON)
}

func normalizeFactoryRunDeps(deps factoryRunDeps) factoryRunDeps {
	if deps.defaultStore == nil {
		deps.defaultStore = defaultFactoryRunDeps.defaultStore
	}
	if deps.newRunID == nil {
		deps.newRunID = defaultFactoryRunDeps.newRunID
	}
	if deps.now == nil {
		deps.now = defaultFactoryRunDeps.now
	}
	if deps.workingDir == nil {
		deps.workingDir = defaultFactoryRunDeps.workingDir
	}
	if deps.currentBranch == nil {
		deps.currentBranch = defaultFactoryRunDeps.currentBranch
	}
	if deps.repoRemote == nil {
		deps.repoRemote = defaultFactoryRunDeps.repoRemote
	}
	if deps.runPipeline == nil {
		deps.runPipeline = defaultFactoryRunDeps.runPipeline
	}
	if deps.runSandbox == nil {
		deps.runSandbox = defaultFactoryRunDeps.runSandbox
	}
	return deps
}

func newFactoryRunRecord(dir string, req factoryRunRequest, deps factoryRunDeps) (factory.RunRecord, string, error) {
	runID, err := deps.newRunID()
	if err != nil {
		return factory.RunRecord{}, "", fmt.Errorf("create factory run ID: %w", err)
	}
	now := deps.now().UTC()
	repoPath, err := deps.workingDir()
	if err != nil {
		return factory.RunRecord{}, "", fmt.Errorf("resolve repository path: %w", err)
	}
	branchName, err := deps.currentBranch(dir)
	if err != nil {
		return factory.RunRecord{}, "", fmt.Errorf("resolve current branch: %w", err)
	}
	baseBranch := strings.TrimSpace(req.BaseBranch)
	if req.Sandbox && baseBranch == "" {
		baseBranch = strings.TrimSpace(branchName)
	}
	repoRemote, err := deps.repoRemote(dir)
	if err != nil {
		return factory.RunRecord{}, "", fmt.Errorf("resolve repository remote: %w", err)
	}
	persistedRepoRemote := credentialStrippedGitRemote(repoRemote)

	return factory.RunRecord{
		RunID:        runID,
		Status:       factory.RunStatusPending,
		ExecutorMode: factoryExecutorModeFromRequest(req),
		Source:       factoryRunSourceFromRequest(req),
		RepoPath:     repoPath,
		RepoRemote:   persistedRepoRemote,
		BranchName:   branchName,
		BaseBranch:   baseBranch,
		CurrentStep:  factory.RunStatusPending,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, repoRemote, nil
}

func factoryExecutorModeFromRequest(req factoryRunRequest) string {
	if req.Sandbox {
		return factory.ExecutorModeSandbox
	}
	return factory.ExecutorModeLocal
}

func createFactoryRunRecord(store factory.Store, record factory.RunRecord) error {
	if err := store.SaveRun(&record); err != nil {
		return fmt.Errorf("create factory run record: %w", err)
	}
	return nil
}

func markFactoryRunInProgress(store factory.Store, record factory.RunRecord, now time.Time) (factory.RunRecord, error) {
	record.Status = factory.RunStatusRunning
	record.CurrentStep = "run"
	record.UpdatedAt = now.UTC()
	if err := store.SaveRun(&record); err != nil {
		return factory.RunRecord{}, fmt.Errorf("mark factory run in progress: %w", err)
	}
	return record, nil
}

func recordFactoryRunArtifacts(store factory.Store, runID, dir string, req factoryRunRequest, snapshot factoryArtifactSnapshot, now time.Time) (factory.RunRecord, error) {
	record, err := store.LoadRun(runID)
	if err != nil {
		return factory.RunRecord{}, fmt.Errorf("load factory run for artifacts: %w", err)
	}

	record.Artifacts = collectFactoryRunArtifacts(store, dir, req, *record, snapshot)
	record.UpdatedAt = now.UTC()
	if err := store.SaveRun(record); err != nil {
		return factory.RunRecord{}, fmt.Errorf("record factory artifacts: %w", err)
	}
	return *record, nil
}

func refreshFactoryRunBranch(store factory.Store, runID, dir string, deps factoryRunDeps, now time.Time) (factory.RunRecord, error) {
	record, err := store.LoadRun(runID)
	if err != nil {
		return factory.RunRecord{}, fmt.Errorf("load factory run for branch refresh: %w", err)
	}
	branchName, err := deps.currentBranch(dir)
	if err != nil {
		return factory.RunRecord{}, fmt.Errorf("refresh factory run branch: %w", err)
	}
	branchName = strings.TrimSpace(branchName)
	if branchName == "" || branchName == strings.TrimSpace(record.BranchName) {
		return *record, nil
	}

	record.BranchName = branchName
	record.UpdatedAt = now.UTC()
	if err := store.SaveRun(record); err != nil {
		return factory.RunRecord{}, fmt.Errorf("refresh factory run branch: %w", err)
	}
	return *record, nil
}

func refreshFactoryRunBranchForMode(store factory.Store, runID, dir string, req factoryRunRequest, deps factoryRunDeps, now time.Time) (factory.RunRecord, error) {
	if req.Sandbox {
		record, err := store.LoadRun(runID)
		if err != nil {
			return factory.RunRecord{}, fmt.Errorf("load factory run for branch refresh: %w", err)
		}
		return *record, nil
	}
	return refreshFactoryRunBranch(store, runID, dir, deps, now)
}

func markFactoryRunSucceeded(store factory.Store, record factory.RunRecord, now time.Time) (factory.RunRecord, error) {
	finishedAt := now.UTC()
	record.Status = factory.RunStatusSucceeded
	record.CurrentStep = "done"
	record.UpdatedAt = finishedAt
	record.FinishedAt = &finishedAt
	record.Failure = nil
	if err := store.SaveRun(&record); err != nil {
		return factory.RunRecord{}, fmt.Errorf("mark factory run succeeded: %w", err)
	}
	return record, nil
}

func markFactoryRunFailed(store factory.Store, record factory.RunRecord, now time.Time, pipelineErr error) (factory.RunRecord, error) {
	finishedAt := now.UTC()
	existingFailure := record.Failure
	failure := newFactoryRunFailureSummary(record.RunID, record.CurrentStep, pipelineErr)
	if existingFailure != nil && record.ExecutorMode == factory.ExecutorModeSandbox {
		preserved := *existingFailure
		if strings.TrimSpace(preserved.Step) == "" {
			preserved.Step = failure.Step
		}
		if strings.TrimSpace(preserved.Category) == "" {
			preserved.Category = failure.Category
		}
		if strings.TrimSpace(preserved.Message) == "" {
			preserved.Message = failure.Message
		}
		if strings.TrimSpace(preserved.SuggestedCommand) == "" {
			preserved.SuggestedCommand = failure.SuggestedCommand
		}
		if preserved.ExitCode == 0 {
			preserved.ExitCode = failure.ExitCode
		}
		failure = preserved
		if command := strings.TrimSpace(existingFailure.SuggestedCommand); command != "" {
			failure.SuggestedCommand = command
		}
	}
	record.Status = factory.RunStatusFailed
	record.CurrentStep = failure.Step
	record.UpdatedAt = finishedAt
	record.FinishedAt = &finishedAt
	record.Failure = &failure
	if err := store.SaveRun(&record); err != nil {
		return factory.RunRecord{}, fmt.Errorf("mark factory run failed: %w", err)
	}
	return record, nil
}

func factorySandboxPipelineRecordError(record factory.RunRecord, fallback error) error {
	if record.Failure != nil {
		if message := strings.TrimSpace(record.Failure.Message); message != "" {
			return errors.New(message)
		}
	}
	return fallback
}

func newFactoryRunFailureSummary(runID, currentStep string, pipelineErr error) factory.FailureSummary {
	category := classifyFactoryRunFailure(pipelineErr)
	failure := factory.FailureSummary{
		Step:             factoryRunFailureStep(currentStep, pipelineErr),
		Category:         category,
		Message:          factoryRunFailureMessage(pipelineErr),
		Recoverable:      factoryRunFailureRecoverable(category),
		SuggestedCommand: factoryRunInspectCommand(runID),
		ExitCode:         factoryRunFailureExitCode(pipelineErr),
	}
	if strings.TrimSpace(failure.Message) == "" {
		failure.Message = "factory run failed"
	}
	return failure
}

func classifyFactoryRunFailure(err error) string {
	if err == nil {
		return factory.FailureCategoryUnknown
	}

	var exitErr *ExitCodeError
	if errors.As(err, &exitErr) && exitErr.Code == ExitCodeValidation {
		return factory.FailureCategoryValidation
	}

	step := autoFailedStep(err)
	switch step {
	case compound.StepValidate:
		return factory.FailureCategoryValidation
	case compound.StepCI:
		return factory.FailureCategoryCI
	case compound.StepBranch:
		return factory.FailureCategoryGit
	}

	message := strings.ToLower(strings.TrimSpace(err.Error()))
	switch {
	case factoryFailureMessageContains(message, "validation", "validate", "invalid"):
		return factory.FailureCategoryValidation
	case factoryFailureMessageContains(message, "engine", "codex", "claude"):
		return factory.FailureCategoryEngine
	case factoryFailureMessageContains(message, "github", "git ", " git", "merge-base", "commit", "branch"):
		return factory.FailureCategoryGit
	case factoryFailureMessageContains(message, " ci", "ci ", "ci:", "ci-", "ci_", "workflow", "status check", "check run"):
		return factory.FailureCategoryCI
	case factoryFailureMessageContains(message, "pipeline") || step != "":
		return factory.FailureCategoryPipeline
	default:
		return factory.FailureCategoryUnknown
	}
}

func factoryRunFailureStep(currentStep string, err error) string {
	if step := autoFailedStep(err); step != "" {
		return step
	}
	if step := strings.TrimSpace(currentStep); step != "" {
		return step
	}
	return "run"
}

func factoryRunFailureMessage(err error) string {
	if err == nil {
		return ""
	}
	return strings.TrimSpace(err.Error())
}

func factoryRunFailureRecoverable(category string) bool {
	switch category {
	case factory.FailureCategoryValidation,
		factory.FailureCategoryPipeline,
		factory.FailureCategoryEngine,
		factory.FailureCategoryGit,
		factory.FailureCategoryCI:
		return true
	default:
		return false
	}
}

func factoryRunFailureExitCode(err error) int {
	var exitErr *ExitCodeError
	if errors.As(err, &exitErr) {
		return exitErr.Code
	}
	var execErr *exec.ExitError
	if errors.As(err, &execErr) {
		return execErr.ExitCode()
	}
	return 0
}

func factoryFailureMessageContains(message string, fragments ...string) bool {
	for _, fragment := range fragments {
		if strings.Contains(message, fragment) {
			return true
		}
	}
	return false
}

func collectFactoryRunArtifacts(store factory.Store, dir string, req factoryRunRequest, record factory.RunRecord, snapshot factoryArtifactSnapshot) []factory.ArtifactReference {
	collector := newFactoryArtifactCollector(dir)
	archived := collectFactoryRunArchivedArtifacts(dir, record.CreatedAt)

	if markdownPath := strings.TrimSpace(req.MarkdownPath); markdownPath != "" {
		collector.addExistingOrArchived("source-markdown", markdownPath, archived)
	}
	if reportPath := strings.TrimSpace(req.ReportPath); reportPath != "" {
		collector.addExistingOrArchived("source-report", reportPath, archived)
	}

	halDir := filepath.Join(dir, template.HalDir)
	canonicalPRDPath := filepath.Join(template.HalDir, template.PRDFile)
	autoStatePath := filepath.Join(template.HalDir, template.AutoStateFile)
	if !collector.addGenerated("canonical-prd", canonicalPRDPath, snapshot) {
		collector.addArchived("canonical-prd", canonicalPRDPath, archived)
	}
	if !collector.addGenerated("auto-state", autoStatePath, snapshot) {
		collector.addArchived("auto-state", autoStatePath, archived)
	}

	if factoryArtifactChangedSinceSnapshot(dir, autoStatePath, snapshot) {
		if state, ok := loadFactoryRunPipelineState(filepath.Join(halDir, template.AutoStateFile)); ok {
			if sourceMarkdown := strings.TrimSpace(state.SourceMarkdown); sourceMarkdown != "" {
				collector.addExistingOrArchived("pipeline-source-markdown", sourceMarkdown, archived)
			}
			if reportPath := strings.TrimSpace(state.ReportPath); reportPath != "" {
				collector.addExistingOrArchived(factoryGeneratedReportArtifactName(reportPath), reportPath, archived)
			}
		}
	}
	for _, state := range archived.pipelineStates {
		if sourceMarkdown := strings.TrimSpace(state.SourceMarkdown); sourceMarkdown != "" {
			collector.addExistingOrArchived("pipeline-source-markdown", sourceMarkdown, archived)
		}
		if reportPath := strings.TrimSpace(state.ReportPath); reportPath != "" {
			collector.addExistingOrArchived(factoryGeneratedReportArtifactName(reportPath), reportPath, archived)
		}
	}

	for _, artifact := range collectFactoryRunReportArtifacts(dir, record.CreatedAt) {
		collector.add(artifact)
	}
	for _, artifact := range archived.reportArtifacts {
		collector.add(artifact)
	}

	if recordPath := factoryRunRecordArtifactPath(store, record.RunID); recordPath != "" {
		collector.add(factory.ArtifactReference{
			Name: "factory-run-record",
			Type: "json",
			Path: recordPath,
		})
	}

	return collector.artifacts
}

type factoryArtifactCollector struct {
	dir       string
	seen      map[string]struct{}
	artifacts []factory.ArtifactReference
}

type factoryArtifactSnapshot map[string]factoryArtifactFileSnapshot

type factoryArtifactFileSnapshot struct {
	exists  bool
	size    int64
	modTime time.Time
	content []byte
}

func snapshotFactoryRunArtifacts(dir string) factoryArtifactSnapshot {
	paths := []string{
		filepath.Join(template.HalDir, template.PRDFile),
		filepath.Join(template.HalDir, template.AutoStateFile),
	}
	snapshot := make(factoryArtifactSnapshot, len(paths))
	for _, path := range paths {
		snapshot[factoryArtifactSnapshotKey(path)] = snapshotFactoryArtifactFile(filepath.Join(dir, path))
	}
	return snapshot
}

func snapshotFactoryArtifactFile(path string) factoryArtifactFileSnapshot {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return factoryArtifactFileSnapshot{}
	}
	content, _ := os.ReadFile(path)
	return factoryArtifactFileSnapshot{
		exists:  true,
		size:    info.Size(),
		modTime: info.ModTime(),
		content: content,
	}
}

func newFactoryArtifactCollector(dir string) *factoryArtifactCollector {
	return &factoryArtifactCollector{
		dir:  dir,
		seen: make(map[string]struct{}),
	}
}

func (c *factoryArtifactCollector) addExisting(name, path string) bool {
	if strings.TrimSpace(path) == "" || !factoryArtifactFileExists(c.resolvePath(path)) {
		return false
	}
	c.add(factory.ArtifactReference{
		Name: name,
		Type: factoryArtifactTypeForPath(path),
		Path: c.displayPath(path),
	})
	return true
}

func (c *factoryArtifactCollector) addExistingOrArchived(name, path string, archived factoryArchivedArtifacts) bool {
	if c.addExisting(name, path) {
		return true
	}
	return c.addArchived(name, path, archived)
}

func (c *factoryArtifactCollector) addArchived(name, path string, archived factoryArchivedArtifacts) bool {
	archivedPath := archived.find(path)
	if archivedPath == "" {
		return false
	}
	return c.addExisting(name, archivedPath)
}

func (c *factoryArtifactCollector) addGenerated(name, path string, snapshot factoryArtifactSnapshot) bool {
	if !factoryArtifactChangedSinceSnapshot(c.dir, path, snapshot) {
		return false
	}
	c.add(factory.ArtifactReference{
		Name: name,
		Type: factoryArtifactTypeForPath(path),
		Path: c.displayPath(path),
	})
	return true
}

func (c *factoryArtifactCollector) add(artifact factory.ArtifactReference) {
	artifact.Name = strings.TrimSpace(artifact.Name)
	artifact.Type = strings.TrimSpace(artifact.Type)
	artifact.Path = strings.TrimSpace(artifact.Path)
	artifact.URL = strings.TrimSpace(artifact.URL)
	if artifact.Name == "" || artifact.Type == "" {
		return
	}

	key := artifact.Name + "\x00" + artifact.Type + "\x00" + artifact.Path + "\x00" + artifact.URL
	if artifact.Path != "" {
		key = "path\x00" + filepath.Clean(artifact.Path)
	}
	if artifact.URL != "" {
		key = "url\x00" + artifact.URL
	}
	if _, ok := c.seen[key]; ok {
		return
	}
	c.seen[key] = struct{}{}
	c.artifacts = append(c.artifacts, artifact)
}

func (c *factoryArtifactCollector) resolvePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(c.dir, path)
}

func (c *factoryArtifactCollector) displayPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		baseDir := c.dir
		if baseDir == "" {
			baseDir = "."
		}
		if absDir, err := filepath.Abs(baseDir); err == nil {
			if rel, err := filepath.Rel(absDir, path); err == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && rel != ".." {
				return filepath.Clean(rel)
			}
		}
		return filepath.Clean(path)
	}
	return filepath.Clean(path)
}

func loadFactoryRunPipelineState(path string) (*compound.PipelineState, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var state compound.PipelineState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, false
	}
	return &state, true
}

func collectFactoryRunReportArtifacts(dir string, startedAt time.Time) []factory.ArtifactReference {
	reportsDir := filepath.Join(dir, template.HalDir, "reports")
	entries, err := os.ReadDir(reportsDir)
	if err != nil {
		return nil
	}

	type reportFile struct {
		name    string
		path    string
		modTime time.Time
	}
	reportFiles := make([]reportFile, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		path := filepath.Join(template.HalDir, "reports", name)
		info, err := entry.Info()
		if err != nil || info.IsDir() {
			continue
		}
		if !startedAt.IsZero() && info.ModTime().Before(startedAt) {
			continue
		}
		reportFiles = append(reportFiles, reportFile{
			name:    name,
			path:    path,
			modTime: info.ModTime(),
		})
	}

	sort.Slice(reportFiles, func(i, j int) bool {
		if !reportFiles[i].modTime.Equal(reportFiles[j].modTime) {
			return reportFiles[i].modTime.Before(reportFiles[j].modTime)
		}
		return reportFiles[i].path < reportFiles[j].path
	})

	artifacts := make([]factory.ArtifactReference, 0, len(reportFiles))
	for _, reportFile := range reportFiles {
		artifacts = append(artifacts, factory.ArtifactReference{
			Name: factoryGeneratedReportArtifactName(reportFile.name),
			Type: factoryArtifactTypeForPath(reportFile.path),
			Path: filepath.Clean(reportFile.path),
		})
	}
	return artifacts
}

type factoryArchivedArtifacts struct {
	dir             string
	byOriginal      map[string]string
	pipelineStates  []compound.PipelineState
	reportArtifacts []factory.ArtifactReference
}

func collectFactoryRunArchivedArtifacts(dir string, startedAt time.Time) factoryArchivedArtifacts {
	archived := factoryArchivedArtifacts{dir: dir, byOriginal: make(map[string]string)}
	archiveRoot := filepath.Join(dir, template.HalDir, "archive")
	entries, err := os.ReadDir(archiveRoot)
	if err != nil {
		return archived
	}

	type archiveDir struct {
		name    string
		modTime time.Time
	}
	dirs := make([]archiveDir, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.IsDir() {
			continue
		}
		if !startedAt.IsZero() && info.ModTime().Before(startedAt) {
			continue
		}
		dirs = append(dirs, archiveDir{name: entry.Name(), modTime: info.ModTime()})
	}
	sort.Slice(dirs, func(i, j int) bool {
		if !dirs[i].modTime.Equal(dirs[j].modTime) {
			return dirs[i].modTime.After(dirs[j].modTime)
		}
		return dirs[i].name > dirs[j].name
	})

	for _, dirEntry := range dirs {
		archiveDirPath := filepath.Join(archiveRoot, dirEntry.name)
		archiveRel := filepath.Join(template.HalDir, "archive", dirEntry.name)
		archived.addFile(filepath.Join(template.HalDir, template.PRDFile), filepath.Join(archiveRel, template.PRDFile), filepath.Join(archiveDirPath, template.PRDFile))
		if archived.addFile(filepath.Join(template.HalDir, template.AutoStateFile), filepath.Join(archiveRel, template.AutoStateFile), filepath.Join(archiveDirPath, template.AutoStateFile)) {
			if state, ok := loadFactoryRunPipelineState(filepath.Join(archiveDirPath, template.AutoStateFile)); ok {
				archived.pipelineStates = append(archived.pipelineStates, *state)
			}
		}

		prdMarkdownPaths, _ := filepath.Glob(filepath.Join(archiveDirPath, "prd-*.md"))
		sort.Strings(prdMarkdownPaths)
		for _, path := range prdMarkdownPaths {
			base := filepath.Base(path)
			archived.addFile(filepath.Join(template.HalDir, base), filepath.Join(archiveRel, base), path)
		}

		reportsDir := filepath.Join(archiveDirPath, "reports")
		reportEntries, err := os.ReadDir(reportsDir)
		if err != nil {
			continue
		}
		for _, reportEntry := range reportEntries {
			name := reportEntry.Name()
			if reportEntry.IsDir() || strings.HasPrefix(name, ".") {
				continue
			}
			info, err := reportEntry.Info()
			if err != nil || info.IsDir() {
				continue
			}
			original := filepath.Join(template.HalDir, "reports", name)
			archivedPath := filepath.Join(archiveRel, "reports", name)
			if archived.addFile(original, archivedPath, filepath.Join(reportsDir, name)) {
				archived.reportArtifacts = append(archived.reportArtifacts, factory.ArtifactReference{
					Name: factoryGeneratedReportArtifactName(name),
					Type: factoryArtifactTypeForPath(archivedPath),
					Path: filepath.Clean(archivedPath),
				})
			}
		}
	}

	return archived
}

func (a *factoryArchivedArtifacts) addFile(originalPath, archivedPath, absolutePath string) bool {
	if strings.TrimSpace(originalPath) == "" || strings.TrimSpace(archivedPath) == "" || !factoryArtifactFileExists(absolutePath) {
		return false
	}
	if a.byOriginal == nil {
		a.byOriginal = make(map[string]string)
	}
	originalPath = filepath.Clean(originalPath)
	archivedPath = filepath.Clean(archivedPath)
	if _, ok := a.byOriginal[originalPath]; !ok {
		a.byOriginal[originalPath] = archivedPath
	}
	return true
}

func (a factoryArchivedArtifacts) find(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || len(a.byOriginal) == 0 {
		return ""
	}
	for _, candidate := range factoryArchiveOriginalCandidates(a.dir, path) {
		if archivedPath := a.byOriginal[candidate]; archivedPath != "" {
			return archivedPath
		}
	}
	return ""
}

func factoryArchiveOriginalCandidates(dir, path string) []string {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." {
		return nil
	}
	candidates := []string{path}
	if filepath.IsAbs(path) {
		baseDir := dir
		if baseDir == "" {
			baseDir = "."
		}
		if absDir, err := filepath.Abs(baseDir); err == nil {
			baseDir = absDir
		}
		if rel, err := filepath.Rel(baseDir, path); err == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && rel != ".." {
			candidates = append(candidates, filepath.Clean(rel))
		}
	}
	if strings.HasPrefix(path, template.HalDir+string(os.PathSeparator)) {
		candidates = append(candidates, filepath.Join(template.HalDir, filepath.Base(path)))
	}
	return candidates
}

func factoryGeneratedReportArtifactName(path string) string {
	name := strings.ToLower(filepath.Base(strings.TrimSpace(path)))
	switch {
	case strings.HasPrefix(name, "review-loop-"):
		return "review-loop-report"
	case strings.HasPrefix(name, "review-"):
		return "review-report"
	case strings.Contains(name, "ci"):
		return "ci-artifact"
	case strings.Contains(name, "pr"):
		return "pr-artifact"
	default:
		return "generated-report"
	}
}

func factoryArtifactTypeForPath(path string) string {
	switch strings.ToLower(filepath.Ext(strings.TrimSpace(path))) {
	case ".json":
		return "json"
	case ".md", ".markdown":
		return "markdown"
	case ".log", ".txt":
		return "text"
	default:
		return "file"
	}
}

func factoryArtifactFileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func factoryArtifactChangedSinceSnapshot(dir, path string, snapshot factoryArtifactSnapshot) bool {
	path = strings.TrimSpace(path)
	if path == "" || !factoryArtifactFileExists(resolveFactoryArtifactPath(dir, path)) {
		return false
	}
	if snapshot == nil {
		return true
	}
	before, ok := snapshot[factoryArtifactSnapshotKey(path)]
	if !ok || !before.exists {
		return true
	}
	after := snapshotFactoryArtifactFile(resolveFactoryArtifactPath(dir, path))
	if !after.exists {
		return false
	}
	if before.size != after.size || !before.modTime.Equal(after.modTime) {
		return true
	}
	return !bytes.Equal(before.content, after.content)
}

func resolveFactoryArtifactPath(dir, path string) string {
	path = strings.TrimSpace(path)
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(dir, path)
}

func factoryArtifactSnapshotKey(path string) string {
	return filepath.Clean(strings.TrimSpace(path))
}

func factoryRunRecordArtifactPath(store factory.Store, runID string) string {
	if strings.TrimSpace(store.RunsDir()) == "" || strings.TrimSpace(runID) == "" {
		return ""
	}
	return filepath.Join(store.RunsDir(), runID+".json")
}

func recordFactoryRunStarted(store factory.Store, record factory.RunRecord) error {
	return appendFactoryRunTimelineEvent(store, record.RunID, record.CreatedAt, factoryTimelineEvent{
		EventType: factory.EventTypeRunCreated,
		Summary:   "Factory run started",
		Metadata: map[string]any{
			"executorMode": record.ExecutorMode,
			"sourceKind":   record.Source.Kind,
			"status":       record.Status,
		},
	})
}

func recordFactoryRunPipelineStarted(store factory.Store, record factory.RunRecord) error {
	return appendFactoryRunTimelineEvent(store, record.RunID, record.UpdatedAt, factoryTimelineEvent{
		EventType: factory.EventTypeStepStarted,
		Summary:   "Local compound pipeline started",
		Metadata: map[string]any{
			"step":   record.CurrentStep,
			"status": record.Status,
		},
	})
}

func recordFactoryRunProgress(store factory.Store, runID string, now time.Time, event factoryRunProgressEvent) error {
	return appendFactoryRunTimelineEvent(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypeCommandOutputSummary,
		Message:   event.Message,
		Summary:   event.Summary,
		Metadata:  event.Metadata,
	})
}

func recordFactoryRunPipelineSucceeded(store factory.Store, runID string, now time.Time) error {
	return appendFactoryRunTimelineEvent(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypeStepEnded,
		Summary:   "Local compound pipeline completed",
		Metadata: map[string]any{
			"step":   "run",
			"status": factory.RunStatusSucceeded,
		},
	})
}

func recordFactoryRunPipelineFailed(store factory.Store, runID string, now time.Time, pipelineErr error) error {
	return appendFactoryRunTimelineEvent(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypeStepEnded,
		Summary:   "Local compound pipeline failed",
		Metadata: map[string]any{
			"step":   "run",
			"status": factory.RunStatusFailed,
			"error":  pipelineErr.Error(),
		},
	})
}

func recordFactoryRunFailureClassified(store factory.Store, runID string, now time.Time, failure factory.FailureSummary) error {
	metadata := map[string]any{
		"step":        failure.Step,
		"category":    failure.Category,
		"recoverable": failure.Recoverable,
	}
	if failure.SuggestedCommand != "" {
		metadata["suggestedCommand"] = failure.SuggestedCommand
	}
	if failure.ExitCode != 0 {
		metadata["exitCode"] = failure.ExitCode
	}

	return appendFactoryRunTimelineEvent(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypeFailureClassification,
		Summary:   "Failure classified",
		Metadata:  metadata,
	})
}

func factoryRunHasFailureClassificationEvent(store factory.Store, runID string) (bool, error) {
	events, err := store.LoadEvents(runID)
	if err != nil {
		return false, fmt.Errorf("load factory timeline %q: %w", runID, err)
	}
	for _, event := range events {
		if event.EventType == factory.EventTypeFailureClassification {
			return true, nil
		}
	}
	return false, nil
}

func appendFactoryRunTimelineEvent(store factory.Store, runID string, timestamp time.Time, event factoryTimelineEvent) error {
	events, err := store.LoadEvents(runID)
	if err != nil {
		return fmt.Errorf("load factory timeline %q: %w", runID, err)
	}

	record := factory.EventRecord{
		Sequence:  nextFactoryRunEventSequence(events),
		RunID:     runID,
		EventType: event.EventType,
		Timestamp: timestamp.UTC(),
		Message:   event.Message,
		Summary:   event.Summary,
		Metadata:  event.Metadata,
	}
	if err := store.AppendEvent(&record); err != nil {
		return fmt.Errorf("append factory timeline event %q: %w", runID, err)
	}
	return nil
}

func nextFactoryRunEventSequence(events []factory.EventRecord) int64 {
	var maxSequence int64
	for _, event := range events {
		if event.Sequence > maxSequence {
			maxSequence = event.Sequence
		}
	}
	return maxSequence + 1
}

func factoryRunSourceFromRequest(req factoryRunRequest) factory.SourceMetadata {
	markdownPath := strings.TrimSpace(req.MarkdownPath)
	reportPath := strings.TrimSpace(req.ReportPath)

	switch {
	case markdownPath != "":
		return factory.SourceMetadata{
			Kind: factory.SourceKindMarkdown,
			Path: markdownPath,
		}
	case reportPath != "":
		return factory.SourceMetadata{
			Kind:       factory.SourceKindReport,
			Path:       reportPath,
			ReportPath: reportPath,
		}
	default:
		return factory.SourceMetadata{
			Kind: factory.SourceKindAutoDiscovery,
		}
	}
}

func runFactoryRunPipeline(ctx context.Context, req factoryRunPipelineRequest) error {
	return runFactoryRunPipelineWithDeps(ctx, req, factoryRunPipelineDeps{
		runAuto: runAutoForFactoryRun,
	})
}

func runFactoryRunPipelineWithDeps(ctx context.Context, req factoryRunPipelineRequest, deps factoryRunPipelineDeps) error {
	if deps.runAuto == nil {
		return fmt.Errorf("factory run auto dependency is required")
	}

	autoReq := factoryRunAutoRequestFromFactoryRequest(req.Request)
	if strings.TrimSpace(autoReq.BaseBranch) == "" {
		autoReq.BaseBranch = strings.TrimSpace(req.Record.BaseBranch)
	}
	autoReq.RecordProgress = req.RecordProgress
	return deps.runAuto(ctx, autoReq)
}

func factoryRunAutoRequestFromFactoryRequest(req factoryRunRequest) factoryRunAutoRequest {
	autoReq := factoryRunAutoRequest{
		ReportPath: strings.TrimSpace(req.ReportPath),
		BaseBranch: strings.TrimSpace(req.BaseBranch),
	}
	if markdownPath := strings.TrimSpace(req.MarkdownPath); markdownPath != "" {
		autoReq.Args = []string{markdownPath}
	}
	return autoReq
}

func runAutoForFactoryRun(ctx context.Context, req factoryRunAutoRequest) error {
	if ctx == nil {
		ctx = context.Background()
	}

	out := io.Writer(io.Discard)
	var progressWriter *factoryRunProgressWriter
	if req.RecordProgress != nil {
		progressWriter = &factoryRunProgressWriter{record: req.RecordProgress}
		out = progressWriter
	}

	cmd := &cobra.Command{Use: "auto"}
	cmd.SetContext(ctx)
	cmd.SetOut(out)
	cmd.SetErr(io.Discard)
	cmd.Flags().Bool("dry-run", false, "")
	cmd.Flags().Bool("resume", false, "")
	cmd.Flags().Bool("no-ci", false, "")
	cmd.Flags().Bool("skip-pr", false, "")
	cmd.Flags().Bool("no-review", false, "")
	cmd.Flags().String("mode", "", "")
	cmd.Flags().Int("review-streak", 0, "")
	cmd.Flags().Int("review-max", 0, "")
	cmd.Flags().String("report", strings.TrimSpace(req.ReportPath), "")
	cmd.Flags().String("engine", "codex", "")
	cmd.Flags().String("base", strings.TrimSpace(req.BaseBranch), "")
	cmd.Flags().Bool("json", false, "")

	err := runAuto(cmd, req.Args)
	if progressWriter != nil {
		if flushErr := progressWriter.Flush(); flushErr != nil {
			return errors.Join(err, flushErr)
		}
	}
	return err
}

type factoryRunProgressWriter struct {
	record   func(factoryRunProgressEvent) error
	pending  string
	lastStep string
	err      error
}

func (w *factoryRunProgressWriter) Write(p []byte) (int, error) {
	if w == nil || w.record == nil {
		return len(p), nil
	}
	w.pending += string(p)
	for {
		idx := strings.IndexByte(w.pending, '\n')
		if idx < 0 {
			break
		}
		line := w.pending[:idx]
		w.pending = w.pending[idx+1:]
		w.handleLine(line)
	}
	return len(p), nil
}

func (w *factoryRunProgressWriter) Flush() error {
	if w == nil {
		return nil
	}
	if strings.TrimSpace(w.pending) != "" {
		w.handleLine(w.pending)
	}
	w.pending = ""
	return w.err
}

func (w *factoryRunProgressWriter) handleLine(line string) {
	if w.err != nil {
		return
	}
	step, ok := factoryRunProgressStepFromLine(line)
	if !ok || step == w.lastStep {
		return
	}
	w.lastStep = step
	w.err = w.record(factoryRunProgressEvent{
		Summary: fmt.Sprintf("Auto %s step started", step),
		Metadata: map[string]any{
			"step":   step,
			"status": "started",
		},
	})
}

func factoryRunProgressStepFromLine(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "Step:") {
		return "", false
	}
	step := strings.TrimSpace(strings.TrimPrefix(line, "Step:"))
	if autoStepIndex(step) < 0 {
		return "", false
	}
	return step, true
}

func factoryRunRequestFromCommand(cmd *cobra.Command, args []string) (factoryRunRequest, error) {
	reportPath := factoryRunReportFlag
	baseBranch := factoryRunBaseFlag
	jsonMode := factoryRunJSONFlag
	sandboxMode := factoryRunSandboxFlag

	if cmd != nil {
		if cmd.Flags().Lookup("report") != nil {
			value, err := cmd.Flags().GetString("report")
			if err != nil {
				return factoryRunRequest{}, err
			}
			reportPath = value
		}
		if cmd.Flags().Lookup("base") != nil {
			value, err := cmd.Flags().GetString("base")
			if err != nil {
				return factoryRunRequest{}, err
			}
			baseBranch = value
		}
		if cmd.Flags().Lookup("json") != nil {
			value, err := cmd.Flags().GetBool("json")
			if err != nil {
				return factoryRunRequest{}, err
			}
			jsonMode = value
		}
		if cmd.Flags().Lookup("sandbox") != nil {
			value, err := cmd.Flags().GetBool("sandbox")
			if err != nil {
				return factoryRunRequest{}, err
			}
			sandboxMode = value
		}
	}

	req, err := parseFactoryRunRequest(args, reportPath, baseBranch, jsonMode, sandboxMode)
	if err != nil {
		return factoryRunRequest{}, exitWithCode(cmd, ExitCodeValidation, err)
	}
	return req, nil
}

func parseFactoryRunRequest(args []string, reportPath, baseBranch string, jsonMode bool, sandboxMode bool) (factoryRunRequest, error) {
	if len(args) > 1 {
		return factoryRunRequest{}, fmt.Errorf("accepts at most 1 arg(s), received %d", len(args))
	}
	if len(args) == 1 && strings.TrimSpace(reportPath) != "" {
		return factoryRunRequest{}, fmt.Errorf("--report cannot be used with a positional PRD markdown path")
	}
	if sandboxMode && strings.TrimSpace(baseBranch) == "" {
		return factoryRunRequest{}, fmt.Errorf("--base is required when --sandbox is set")
	}

	req := factoryRunRequest{
		ReportPath: reportPath,
		BaseBranch: baseBranch,
		Sandbox:    sandboxMode,
		JSON:       jsonMode,
	}
	if len(args) == 1 {
		req.MarkdownPath = args[0]
	}
	return req, nil
}

func runFactoryList(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	jsonMode := factoryListJSONFlag

	if cmd != nil {
		out = cmd.OutOrStdout()
		if cmd.Flags().Lookup("json") != nil {
			v, err := cmd.Flags().GetBool("json")
			if err != nil {
				return err
			}
			jsonMode = v
		}
	}

	return runFactoryListWithDeps(out, jsonMode, defaultFactoryListDeps)
}

func runFactoryListWithDeps(out io.Writer, jsonMode bool, deps factoryListDeps) error {
	if out == nil {
		out = io.Discard
	}
	if deps.defaultStore == nil {
		return fmt.Errorf("factory store dependency is required")
	}

	store, err := deps.defaultStore()
	if err != nil {
		return fmt.Errorf("open factory store: %w", err)
	}
	records, err := store.ListRuns()
	if err != nil {
		return fmt.Errorf("list factory runs: %w", err)
	}

	if jsonMode {
		return renderFactoryListJSON(out, records)
	}

	renderFactoryListTable(out, records)
	return nil
}

func runFactoryStatus(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	jsonMode := factoryStatusJSONFlag

	if cmd != nil {
		out = cmd.OutOrStdout()
		if cmd.Flags().Lookup("json") != nil {
			v, err := cmd.Flags().GetBool("json")
			if err != nil {
				return err
			}
			jsonMode = v
		}
	}

	return runFactoryStatusWithDeps(out, args[0], jsonMode, defaultFactoryStatusDeps)
}

func runFactoryStatusWithDeps(out io.Writer, runID string, jsonMode bool, deps factoryStatusDeps) error {
	if out == nil {
		out = io.Discard
	}
	if deps.defaultStore == nil {
		return fmt.Errorf("factory store dependency is required")
	}

	store, err := deps.defaultStore()
	if err != nil {
		return fmt.Errorf("open factory store: %w", err)
	}
	record, err := store.LoadRun(runID)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("factory run %q not found", runID)
	}
	if err != nil {
		return fmt.Errorf("load factory run %q: %w", runID, err)
	}
	events, err := store.LoadEvents(runID)
	if err != nil {
		return fmt.Errorf("load factory timeline %q: %w", runID, err)
	}
	if events == nil {
		events = []factory.EventRecord{}
	}

	if jsonMode {
		return renderFactoryStatusJSON(out, *record, events)
	}

	renderFactoryStatusTable(out, *record, events)
	return nil
}

func renderFactoryListJSON(out io.Writer, records []factory.RunRecord) error {
	summaries := make([]FactoryRunSummary, 0, len(records))
	for _, record := range records {
		summaries = append(summaries, summarizeFactoryRun(record))
	}

	resp := FactoryListResponse{
		ContractVersion: FactoryListContractVersion,
		Runs:            summaries,
	}
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal factory list: %w", err)
	}
	fmt.Fprintln(out, string(data))
	return nil
}

func renderFactoryStatusJSON(out io.Writer, record factory.RunRecord, events []factory.EventRecord) error {
	resp := FactoryStatusResponse{
		ContractVersion: FactoryStatusContractVersion,
		Run:             record,
		Timeline:        events,
	}
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal factory status: %w", err)
	}
	fmt.Fprintln(out, string(data))
	return nil
}

func renderFactoryRunResult(out io.Writer, store factory.Store, runID string, jsonMode bool) error {
	record, err := store.LoadRun(runID)
	if err != nil {
		return fmt.Errorf("load factory run result %q: %w", runID, err)
	}
	events, err := store.LoadEvents(runID)
	if err != nil {
		return fmt.Errorf("load factory timeline result %q: %w", runID, err)
	}
	if events == nil {
		events = []factory.EventRecord{}
	}
	resp := newFactoryRunResponse(*record, events)
	if jsonMode {
		return renderFactoryRunJSON(out, resp)
	}
	return renderFactoryRunSummary(out, resp)
}

func summarizeFactoryRun(record factory.RunRecord) FactoryRunSummary {
	return FactoryRunSummary{
		RunID:         record.RunID,
		Status:        record.Status,
		Source:        record.Source,
		RepoPath:      record.RepoPath,
		RepoRemote:    record.RepoRemote,
		BranchName:    record.BranchName,
		BaseBranch:    record.BaseBranch,
		SandboxName:   record.SandboxName,
		CurrentStep:   record.CurrentStep,
		CreatedAt:     record.CreatedAt,
		UpdatedAt:     record.UpdatedAt,
		FinishedAt:    record.FinishedAt,
		ArtifactCount: len(record.Artifacts),
		Failure:       record.Failure,
	}
}

func renderFactoryListTable(out io.Writer, records []factory.RunRecord) {
	if len(records) == 0 {
		fmt.Fprintln(out, "No factory runs found.")
		return
	}

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "RUN ID\tSTATUS\tBRANCH\tSTEP\tUPDATED")
	for _, record := range records {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			record.RunID,
			record.Status,
			record.BranchName,
			record.CurrentStep,
			formatFactoryListTime(record.UpdatedAt),
		)
	}
	_ = w.Flush()
}

func renderFactoryStatusTable(out io.Writer, record factory.RunRecord, events []factory.EventRecord) {
	fmt.Fprintf(out, "Run ID: %s\n", record.RunID)
	fmt.Fprintf(out, "Status: %s\n", record.Status)
	fmt.Fprintf(out, "Branch: %s\n", record.BranchName)
	fmt.Fprintf(out, "Step: %s\n", record.CurrentStep)
	fmt.Fprintf(out, "Updated: %s\n", formatFactoryListTime(record.UpdatedAt))
	fmt.Fprintf(out, "Timeline events: %d\n", len(events))
	if len(events) == 0 {
		return
	}

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SEQUENCE\tTYPE\tTIMESTAMP\tSUMMARY")
	for _, event := range events {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n",
			event.Sequence,
			event.EventType,
			formatFactoryListTime(event.Timestamp),
			event.Summary,
		)
	}
	_ = w.Flush()
}

func formatFactoryListTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func readGitRemoteOptionalInDir(dir string) (string, error) {
	cmd := exec.Command("git", "config", "--get", "remote.origin.url")
	if strings.TrimSpace(dir) != "" {
		cmd.Dir = dir
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return "", nil
		}
		return "", fmt.Errorf("read git remote origin: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}
