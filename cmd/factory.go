package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"os/exec"
	pathpkg "path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/doctor"
	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/status"
	"github.com/jywlabs/hal/internal/template"
	"github.com/jywlabs/hal/internal/verify"
	"github.com/spf13/cobra"
)

const (
	FactoryRunContractVersion       = "factory-run-v1"
	FactoryListContractVersion      = "factory-list-v1"
	FactoryStatusContractVersion    = "factory-status-v1"
	FactoryArtifactsContractVersion = "factory-artifacts-v1"
)

var factoryListJSONFlag bool
var factoryStatusJSONFlag bool
var factoryArtifactsJSONFlag bool
var factoryRunReportFlag string
var factoryRunBaseFlag string
var factoryRunSandboxNameFlag string
var factoryRunJSONFlag bool
var factoryRunSandboxFlag bool

var factoryCmd = &cobra.Command{
	Use:   "factory",
	Short: "Run and inspect factory workflows",
	Long: `Run local factory workflows and inspect durable factory run history stored
under Hal's global config directory.

Factory run wraps the local auto pipeline while list and status read the global factory store,
which is separate from per-project .hal runtime state. Queue commands manage
pending local factory work in the same global store.`,
	Example: `  hal factory run .hal/prd-feature.md
  hal factory run --report .hal/reports/analysis.md --json
  hal factory list
  hal factory list --json
  hal factory status <run-id> --json
  hal factory artifacts <run-id>
  hal factory trigger --repo . --prd .hal/prd-feature.md --json
  hal factory queue list --json`,
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
sandbox-backed execution, --sandbox-name <name> to target a specific sandbox,
and --json for machine-readable factory-run-v1 output.`,
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

var factoryArtifactsCmd = &cobra.Command{
	Use:   "artifacts <run-id>",
	Short: "List artifacts for a stored factory run",
	Args:  exactArgsValidation(1),
	Long: `List collected artifacts for one stored factory run from the global factory store.

The output includes each artifact's display path, store-backed path when
available, type, warning state, and summary metadata. Use --json for
machine-readable output following the factory-artifacts-v1 contract. JSON
output omits raw source paths and remote URLs from artifact records.`,
	Example: `  hal factory artifacts run-20260620-001
  hal factory artifacts run-20260620-001 --json`,
	RunE: runFactoryArtifacts,
}

func init() {
	factoryRunCmd.Flags().StringVar(&factoryRunReportFlag, "report", "", "Start from an analysis report path")
	factoryRunCmd.Flags().StringVar(&factoryRunBaseFlag, "base", "", "Target base branch for follow-up review or CI")
	factoryRunCmd.Flags().StringVar(&factoryRunSandboxNameFlag, "sandbox-name", "", "Target sandbox name for sandbox-backed execution")
	factoryRunCmd.Flags().BoolVar(&factoryRunSandboxFlag, "sandbox", false, "Run the factory executor in a managed sandbox")
	factoryRunCmd.Flags().BoolVar(&factoryRunJSONFlag, "json", false, "Output machine-readable JSON (factory-run-v1 contract)")
	factoryListCmd.Flags().BoolVar(&factoryListJSONFlag, "json", false, "Output machine-readable JSON (factory-list-v1 contract)")
	factoryStatusCmd.Flags().BoolVar(&factoryStatusJSONFlag, "json", false, "Output machine-readable JSON (factory-status-v1 contract)")
	factoryArtifactsCmd.Flags().BoolVar(&factoryArtifactsJSONFlag, "json", false, "Output machine-readable JSON (factory-artifacts-v1 contract)")
	configureFactoryTriggerCommand()
	configureFactoryQueueCommands()
	factoryCmd.AddCommand(factoryRunCmd)
	factoryCmd.AddCommand(factoryListCmd)
	factoryCmd.AddCommand(factoryStatusCmd)
	factoryCmd.AddCommand(factoryArtifactsCmd)
	factoryCmd.AddCommand(factoryTriggerCmd)
	factoryCmd.AddCommand(factoryQueueCmd)
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

type factoryArtifactsDeps struct {
	defaultStore func() (factory.Store, error)
}

var defaultFactoryArtifactsDeps = factoryArtifactsDeps{
	defaultStore: factory.DefaultStore,
}

type factoryRunDeps struct {
	defaultStore    func() (factory.Store, error)
	newRunID        func() (string, error)
	now             func() time.Time
	workingDir      func() (string, error)
	currentBranch   func(string) (string, error)
	repoRemote      func(string) (string, error)
	runPipeline     func(context.Context, factoryRunPipelineRequest) error
	loadVerify      func(string) (*verify.Config, error)
	runVerify       func(context.Context, *verify.Config) (*verify.Result, error)
	runSandbox      func(context.Context, factorySandboxExecutorRequest) error
	statusSnapshot  func(string) (factorySnapshotArtifact, error)
	doctorSnapshot  func(string) (factorySnapshotArtifact, error)
	sandboxCopier   factory.SandboxArtifactCopier
	sandboxRequests func(string, factory.RunRecord) []factory.SandboxArtifactRequest
}

type factoryRunPipelineRequest struct {
	RunID          string
	WorkDir        string
	Request        factoryRunRequest
	Record         factory.RunRecord
	Store          factory.Store
	RecordProgress func(factoryRunProgressEvent) error
}

var defaultFactoryRunDeps = factoryRunDeps{
	defaultStore:   factory.DefaultStore,
	newRunID:       sandbox.NewV7,
	now:            time.Now,
	workingDir:     os.Getwd,
	currentBranch:  compound.CurrentBranchOptionalInDir,
	repoRemote:     readGitRemoteOptionalInDir,
	runPipeline:    runFactoryRunPipeline,
	loadVerify:     verify.LoadConfig,
	runVerify:      verify.Run,
	statusSnapshot: defaultFactoryStatusSnapshot,
	doctorSnapshot: defaultFactoryDoctorSnapshot,
	runSandbox: func(ctx context.Context, req factorySandboxExecutorRequest) error {
		return runFactorySandboxExecutorWithDeps(ctx, req, defaultFactorySandboxExecutorDeps)
	},
}

type factoryRunRequest struct {
	MarkdownPath string
	ReportPath   string
	BaseBranch   string
	SandboxName  string
	Sandbox      bool
	JSON         bool
}

type factoryRunAutoRequest struct {
	Args           []string
	WorkDir        string
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

type factorySnapshotArtifact struct {
	Name     string
	Path     string
	Data     []byte
	Summary  map[string]any
	Warnings []string
}

type factoryPROutcomeArtifact struct {
	PullRequestURL string `json:"pullRequestUrl,omitempty"`
	Number         int    `json:"number,omitempty"`
	Title          string `json:"title,omitempty"`
	HeadRef        string `json:"headRef,omitempty"`
	BaseRef        string `json:"baseRef,omitempty"`
	Reused         bool   `json:"reused,omitempty"`
	BranchName     string `json:"branchName,omitempty"`
}

type factoryCIOutcomeArtifact struct {
	Status       string `json:"status,omitempty"`
	Reason       string `json:"reason,omitempty"`
	FixAttempts  int    `json:"fixAttempts,omitempty"`
	FixesApplied int    `json:"fixesApplied,omitempty"`
	BranchName   string `json:"branchName,omitempty"`
}

type factoryRunExecutionDeps struct {
	now             func() time.Time
	currentBranch   func(string) (string, error)
	runPipeline     func(context.Context, factoryRunPipelineRequest) error
	loadVerify      func(string) (*verify.Config, error)
	runVerify       func(context.Context, *verify.Config) (*verify.Result, error)
	runSandbox      func(context.Context, factorySandboxExecutorRequest) error
	statusSnapshot  func(string) (factorySnapshotArtifact, error)
	doctorSnapshot  func(string) (factorySnapshotArtifact, error)
	sandboxCopier   factory.SandboxArtifactCopier
	sandboxRequests func(string, factory.RunRecord) []factory.SandboxArtifactRequest
}

type factoryRunExecutionResult struct {
	Record factory.RunRecord
	Render bool
}

// FactoryListResponse is the machine-readable JSON output for hal factory list --json.
type FactoryListResponse struct {
	ContractVersion string              `json:"contractVersion"`
	Runs            []FactoryRunSummary `json:"runs"`
}

// FactoryStatusResponse is the machine-readable JSON output for hal factory status --json.
type FactoryStatusResponse struct {
	ContractVersion string                `json:"contractVersion"`
	Run             FactoryStatusRun      `json:"run"`
	Timeline        []factory.EventRecord `json:"timeline"`
}

// FactoryStatusRun is the safe run surface for hal factory status --json. It
// mirrors factory.RunRecord but uses sanitized artifact summaries.
type FactoryStatusRun struct {
	RunID        string                      `json:"runId"`
	Status       string                      `json:"status"`
	ExecutorMode string                      `json:"executorMode,omitempty"`
	Source       factory.SourceMetadata      `json:"source"`
	RepoPath     string                      `json:"repoPath"`
	RepoRemote   string                      `json:"repoRemote"`
	BranchName   string                      `json:"branchName"`
	BaseBranch   string                      `json:"baseBranch"`
	SandboxName  string                      `json:"sandboxName,omitempty"`
	Sandbox      *factory.SandboxMetadata    `json:"sandbox,omitempty"`
	CurrentStep  string                      `json:"currentStep"`
	CreatedAt    time.Time                   `json:"createdAt"`
	UpdatedAt    time.Time                   `json:"updatedAt"`
	FinishedAt   *time.Time                  `json:"finishedAt,omitempty"`
	Artifacts    []FactoryArtifactSummary    `json:"artifacts,omitempty"`
	Verification *factory.VerificationRecord `json:"verification,omitempty"`
	Failure      *factory.FailureSummary     `json:"failure,omitempty"`
}

// FactoryArtifactsResponse is the machine-readable JSON output for
// hal factory artifacts <run-id> --json.
type FactoryArtifactsResponse struct {
	ContractVersion string                   `json:"contractVersion"`
	RunID           string                   `json:"runId"`
	Artifacts       []FactoryArtifactSummary `json:"artifacts"`
	Warnings        []string                 `json:"warnings"`
	Summary         FactoryArtifactsSummary  `json:"summary"`
}

// FactoryArtifactSummary is the safe artifact list surface for one stored
// artifact. It intentionally omits sourcePath because it can contain
// workspace-local paths. URL is only populated by contract surfaces that expose
// sanitized remote artifact URLs.
type FactoryArtifactSummary struct {
	ID         string         `json:"id,omitempty"`
	Name       string         `json:"name"`
	Type       string         `json:"type"`
	Path       string         `json:"path,omitempty"`
	StoredPath string         `json:"storedPath,omitempty"`
	URL        string         `json:"url,omitempty"`
	SizeBytes  *int64         `json:"sizeBytes,omitempty"`
	CreatedAt  *time.Time     `json:"createdAt,omitempty"`
	Summary    map[string]any `json:"summary,omitempty"`
	Warnings   []string       `json:"warnings,omitempty"`
	Partial    bool           `json:"partial,omitempty"`
}

// FactoryArtifactsSummary captures aggregate artifact counts for the JSON
// surface.
type FactoryArtifactsSummary struct {
	Total    int `json:"total"`
	Partial  int `json:"partial"`
	Warnings int `json:"warnings"`
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

	if _, err := parseFactoryRunRequest(args, reportPath, "", "", false, false); err != nil {
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

	result, execErr := executeFactoryRun(ctx, dir, req, store, record, out, bootstrapRepositoryURL, factoryRunExecutionDeps{
		now:             deps.now,
		currentBranch:   deps.currentBranch,
		runPipeline:     deps.runPipeline,
		loadVerify:      deps.loadVerify,
		runVerify:       deps.runVerify,
		runSandbox:      deps.runSandbox,
		statusSnapshot:  deps.statusSnapshot,
		doctorSnapshot:  deps.doctorSnapshot,
		sandboxCopier:   deps.sandboxCopier,
		sandboxRequests: deps.sandboxRequests,
	})
	if result.Render {
		if renderErr := renderFactoryRunResult(out, store, result.Record.RunID, req.JSON); renderErr != nil {
			if execErr != nil {
				return errors.Join(execErr, renderErr)
			}
			return renderErr
		}
	}
	return execErr
}

func executeFactoryRun(ctx context.Context, dir string, req factoryRunRequest, store factory.Store, record factory.RunRecord, out io.Writer, bootstrapRepositoryURL string, deps factoryRunExecutionDeps) (factoryRunExecutionResult, error) {
	deps = normalizeFactoryRunExecutionDeps(deps)
	if deps.runPipeline == nil {
		return factoryRunExecutionResult{Record: record}, fmt.Errorf("factory run pipeline dependency is required")
	}
	if req.Sandbox && deps.runSandbox == nil {
		return factoryRunExecutionResult{Record: record}, fmt.Errorf("factory sandbox executor dependency is required")
	}

	runningRecord, err := markFactoryRunInProgress(store, record, deps.now())
	if err != nil {
		return factoryRunExecutionResult{Record: record}, err
	}
	if err := recordFactoryRunPipelineStarted(store, runningRecord); err != nil {
		return factoryRunExecutionResult{Record: runningRecord}, err
	}

	pipelineReq := factoryRunPipelineRequest{
		RunID:   runningRecord.RunID,
		WorkDir: dir,
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
			SandboxName:            req.SandboxName,
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
		if refreshedRecord, branchErr := refreshFactoryRunBranchForMode(store, runningRecord.RunID, dir, req, deps.currentBranch, failedAt); branchErr != nil {
			recordErrs = append(recordErrs, branchErr)
		} else {
			failedRecord = refreshedRecord
		}
		if artifactRecord, artifactErr := recordFactoryRunArtifacts(ctx, store, runningRecord.RunID, dir, req, artifactSnapshot, failedAt, deps); artifactErr != nil {
			recordErrs = append(recordErrs, fmt.Errorf("record factory artifacts: %w", artifactErr))
			if reloadedRecord, loadErr := store.LoadRun(runningRecord.RunID); loadErr != nil {
				recordErrs = append(recordErrs, fmt.Errorf("reload factory run after artifact failure: %w", loadErr))
			} else {
				failedRecord = *reloadedRecord
			}
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
		if artifactRecord, artifactErr := recordFactoryRunRecordArtifact(store, failedRecord); artifactErr != nil {
			recordErrs = append(recordErrs, artifactErr)
		} else {
			failedRecord = artifactRecord
		}
		if len(recordErrs) > 0 {
			return factoryRunExecutionResult{Record: failedRecord}, errors.Join(append([]error{runErr}, recordErrs...)...)
		}
		return factoryRunExecutionResult{Record: failedRecord, Render: true}, runErr
	}

	completedAt := deps.now()
	completedRecord, err := refreshFactoryRunBranchForMode(store, runningRecord.RunID, dir, req, deps.currentBranch, completedAt)
	if err != nil {
		return factoryRunExecutionResult{Record: runningRecord}, err
	}
	artifactRecord, err := recordFactoryRunArtifacts(ctx, store, runningRecord.RunID, dir, req, artifactSnapshot, completedAt, deps)
	if err != nil {
		artifactErr := fmt.Errorf("record factory artifacts: %w", err)
		failedRecord := completedRecord
		var recordErrs []error
		if reloadedRecord, loadErr := store.LoadRun(runningRecord.RunID); loadErr != nil {
			recordErrs = append(recordErrs, fmt.Errorf("reload factory run after artifact failure: %w", loadErr))
		} else {
			failedRecord = *reloadedRecord
		}
		if markedRecord, failureErr := markFactoryRunFailed(store, failedRecord, completedAt, artifactErr); failureErr != nil {
			recordErrs = append(recordErrs, failureErr)
		} else {
			failedRecord = markedRecord
		}
		if failedRecord.Failure != nil {
			if eventErr := recordFactoryRunFailureClassified(store, failedRecord.RunID, completedAt, *failedRecord.Failure); eventErr != nil {
				recordErrs = append(recordErrs, fmt.Errorf("record factory failure classification event: %w", eventErr))
			}
		}
		if artifactRecord, artifactErr := recordFactoryRunRecordArtifact(store, failedRecord); artifactErr != nil {
			recordErrs = append(recordErrs, artifactErr)
		} else {
			failedRecord = artifactRecord
		}
		if len(recordErrs) > 0 {
			return factoryRunExecutionResult{Record: failedRecord}, errors.Join(append([]error{artifactErr}, recordErrs...)...)
		}
		return factoryRunExecutionResult{Record: failedRecord, Render: true}, artifactErr
	}
	completedRecord = artifactRecord

	if !req.Sandbox {
		completedRecord, completedAt, err = recordFactoryRunVerification(ctx, store, completedRecord, dir, deps)
		if err != nil {
			failedRecord, failureErr := markFactoryRunFailed(store, completedRecord, completedAt, err)
			var recordErrs []error
			if failureErr != nil {
				recordErrs = append(recordErrs, failureErr)
			}
			if eventErr := recordFactoryRunVerificationFailed(store, failedRecord.RunID, completedAt, err); eventErr != nil {
				recordErrs = append(recordErrs, fmt.Errorf("record factory verification failure event: %w", eventErr))
			}
			if failedRecord.Failure != nil {
				if eventErr := recordFactoryRunFailureClassified(store, failedRecord.RunID, completedAt, *failedRecord.Failure); eventErr != nil {
					recordErrs = append(recordErrs, fmt.Errorf("record factory failure classification event: %w", eventErr))
				}
			}
			if artifactRecord, artifactErr := recordFactoryRunRecordArtifact(store, failedRecord); artifactErr != nil {
				recordErrs = append(recordErrs, artifactErr)
			} else {
				failedRecord = artifactRecord
			}
			if len(recordErrs) > 0 {
				return factoryRunExecutionResult{Record: failedRecord}, errors.Join(append([]error{err}, recordErrs...)...)
			}
			return factoryRunExecutionResult{Record: failedRecord, Render: true}, err
		}
	}

	completedRecord, err = markFactoryRunSucceeded(store, completedRecord, completedAt)
	if err != nil {
		return factoryRunExecutionResult{Record: completedRecord}, err
	}
	if err := recordFactoryRunPipelineSucceeded(store, completedRecord.RunID, completedAt); err != nil {
		return factoryRunExecutionResult{Record: completedRecord}, err
	}
	runRecordArtifact, err := recordFactoryRunRecordArtifact(store, completedRecord)
	if err != nil {
		artifactErr := fmt.Errorf("record factory run artifact: %w", err)
		failedRecord := completedRecord
		var recordErrs []error
		if markedRecord, failureErr := markFactoryRunFailed(store, failedRecord, completedAt, artifactErr); failureErr != nil {
			recordErrs = append(recordErrs, failureErr)
		} else {
			failedRecord = markedRecord
		}
		if failedRecord.Failure != nil {
			if eventErr := recordFactoryRunFailureClassified(store, failedRecord.RunID, completedAt, *failedRecord.Failure); eventErr != nil {
				recordErrs = append(recordErrs, fmt.Errorf("record factory failure classification event: %w", eventErr))
			}
		}
		if len(recordErrs) > 0 {
			return factoryRunExecutionResult{Record: failedRecord}, errors.Join(append([]error{artifactErr}, recordErrs...)...)
		}
		return factoryRunExecutionResult{Record: failedRecord, Render: true}, artifactErr
	}
	completedRecord = runRecordArtifact
	return factoryRunExecutionResult{Record: completedRecord, Render: true}, nil
}

func normalizeFactoryRunExecutionDeps(deps factoryRunExecutionDeps) factoryRunExecutionDeps {
	if deps.now == nil {
		deps.now = defaultFactoryRunDeps.now
	}
	if deps.currentBranch == nil {
		deps.currentBranch = defaultFactoryRunDeps.currentBranch
	}
	if deps.runPipeline == nil {
		deps.runPipeline = defaultFactoryRunDeps.runPipeline
	}
	if deps.loadVerify == nil {
		deps.loadVerify = defaultFactoryRunDeps.loadVerify
	}
	if deps.runVerify == nil {
		deps.runVerify = defaultFactoryRunDeps.runVerify
	}
	if deps.runSandbox == nil {
		deps.runSandbox = defaultFactoryRunDeps.runSandbox
	}
	if deps.statusSnapshot == nil {
		deps.statusSnapshot = defaultFactoryRunDeps.statusSnapshot
	}
	if deps.doctorSnapshot == nil {
		deps.doctorSnapshot = defaultFactoryRunDeps.doctorSnapshot
	}
	if deps.sandboxRequests == nil {
		deps.sandboxRequests = defaultFactorySandboxArtifactRequests
	}
	return deps
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
	if deps.loadVerify == nil {
		deps.loadVerify = defaultFactoryRunDeps.loadVerify
	}
	if deps.runVerify == nil {
		deps.runVerify = defaultFactoryRunDeps.runVerify
	}
	if deps.runSandbox == nil {
		deps.runSandbox = defaultFactoryRunDeps.runSandbox
	}
	if deps.statusSnapshot == nil {
		deps.statusSnapshot = defaultFactoryRunDeps.statusSnapshot
	}
	if deps.doctorSnapshot == nil {
		deps.doctorSnapshot = defaultFactoryRunDeps.doctorSnapshot
	}
	if deps.sandboxRequests == nil {
		deps.sandboxRequests = defaultFactorySandboxArtifactRequests
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
	repoPath, err = filepath.Abs(strings.TrimSpace(repoPath))
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

func recordFactoryRunArtifacts(ctx context.Context, store factory.Store, runID, dir string, req factoryRunRequest, snapshot factoryArtifactSnapshot, now time.Time, deps factoryRunExecutionDeps) (factory.RunRecord, error) {
	record, err := store.LoadRun(runID)
	if err != nil {
		return factory.RunRecord{}, fmt.Errorf("load factory run for artifacts: %w", err)
	}

	snapshots, cleanup, err := materializeFactorySnapshotArtifacts(dir, deps)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return factory.RunRecord{}, err
	}
	if record.ExecutorMode != factory.ExecutorModeSandbox {
		outcomes, outcomeCleanup, err := materializeFactoryOutcomeArtifacts(dir, record.CreatedAt, snapshot)
		if outcomeCleanup != nil {
			defer outcomeCleanup()
		}
		if err != nil {
			return factory.RunRecord{}, err
		}
		snapshots = append(snapshots, outcomes...)
	}

	if err := collectAndStoreFactoryRunArtifacts(store, dir, req, *record, snapshot, snapshots); err != nil {
		return factory.RunRecord{}, err
	}
	if err := collectAndStoreFactorySandboxArtifacts(ctx, store, dir, *record, deps); err != nil {
		return factory.RunRecord{}, err
	}
	if record.ExecutorMode == factory.ExecutorModeSandbox {
		sandboxRecord, err := store.LoadRun(runID)
		if err != nil {
			return factory.RunRecord{}, fmt.Errorf("reload sandbox factory run artifacts: %w", err)
		}
		outcomes, outcomeCleanup, err := materializeFactorySandboxOutcomeArtifacts(store, *sandboxRecord)
		if outcomeCleanup != nil {
			defer outcomeCleanup()
		}
		if err != nil {
			return factory.RunRecord{}, err
		}
		if err := storeFactoryOutcomeArtifacts(store, *sandboxRecord, outcomes); err != nil {
			return factory.RunRecord{}, err
		}
	}
	record, err = store.LoadRun(runID)
	if err != nil {
		return factory.RunRecord{}, fmt.Errorf("reload factory run artifacts: %w", err)
	}
	record.UpdatedAt = now.UTC()
	if err := store.SaveRun(record); err != nil {
		return factory.RunRecord{}, fmt.Errorf("record factory artifacts: %w", err)
	}
	return *record, nil
}

func refreshFactoryRunBranch(store factory.Store, runID, dir string, currentBranch func(string) (string, error), now time.Time) (factory.RunRecord, error) {
	record, err := store.LoadRun(runID)
	if err != nil {
		return factory.RunRecord{}, fmt.Errorf("load factory run for branch refresh: %w", err)
	}
	if currentBranch == nil {
		currentBranch = defaultFactoryRunDeps.currentBranch
	}
	branchName, err := currentBranch(dir)
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

func recordFactoryRunVerification(ctx context.Context, store factory.Store, record factory.RunRecord, dir string, deps factoryRunExecutionDeps) (factory.RunRecord, time.Time, error) {
	startedAt := deps.now()
	record.CurrentStep = "verify"
	record.UpdatedAt = startedAt.UTC()
	if err := store.SaveRun(&record); err != nil {
		return record, deps.now(), fmt.Errorf("mark factory run verifying: %w", err)
	}

	cfg, err := deps.loadVerify(dir)
	if err != nil {
		return record, deps.now(), fmt.Errorf("load verification config: %w", err)
	}
	if cfg == nil || len(cfg.Checks) == 0 {
		return record, deps.now(), nil
	}

	result, err := deps.runVerify(ctx, cfg)
	finishedAt := deps.now()
	if err != nil {
		return record, finishedAt, fmt.Errorf("run verification: %w", err)
	}
	if result == nil {
		return record, finishedAt, fmt.Errorf("run verification: no result")
	}

	record.Verification = &factory.VerificationRecord{
		Summary:   result.Summary,
		Artifacts: result.Artifacts,
	}
	record.UpdatedAt = finishedAt.UTC()
	if err := store.SaveRun(&record); err != nil {
		return record, finishedAt, fmt.Errorf("record factory verification: %w", err)
	}
	if err := collectAndStoreFactoryVerificationArtifacts(store, dir, record.RunID, result.Artifacts); err != nil {
		if updatedRecord, loadErr := store.LoadRun(record.RunID); loadErr == nil {
			record = *updatedRecord
		} else {
			err = errors.Join(err, fmt.Errorf("reload factory run after verification artifact failure: %w", loadErr))
		}
		return record, finishedAt, err
	}
	updatedRecord, err := store.LoadRun(record.RunID)
	if err != nil {
		return record, finishedAt, fmt.Errorf("reload factory run verification artifacts: %w", err)
	}
	record = *updatedRecord
	if err := recordFactoryRunVerificationResult(store, record.RunID, finishedAt, *result); err != nil {
		return record, finishedAt, fmt.Errorf("record factory verification event: %w", err)
	}
	if result.Status == verify.StatusFail {
		return record, finishedAt, newFactoryRunVerificationFailure(result)
	}
	return record, finishedAt, nil
}

func defaultFactoryStatusSnapshot(dir string) (factorySnapshotArtifact, error) {
	result := status.Get(dir)
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return factorySnapshotArtifact{}, fmt.Errorf("marshal status snapshot: %w", err)
	}
	return factorySnapshotArtifact{
		Name: "status-snapshot",
		Path: filepath.ToSlash(filepath.Join("factory", "status-snapshot.json")),
		Data: append(data, '\n'),
		Summary: map[string]any{
			"snapshotKind":  "status",
			"workflowTrack": result.WorkflowTrack,
			"state":         result.State,
			"summary":       result.Summary,
		},
	}, nil
}

func defaultFactoryDoctorSnapshot(dir string) (factorySnapshotArtifact, error) {
	engine, _ := compound.LoadDefaultEngine(dir)
	result := doctor.Run(doctor.Options{
		Dir:    dir,
		Engine: engine,
	})
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return factorySnapshotArtifact{}, fmt.Errorf("marshal doctor snapshot: %w", err)
	}
	return factorySnapshotArtifact{
		Name: "doctor-snapshot",
		Path: filepath.ToSlash(filepath.Join("factory", "doctor-snapshot.json")),
		Data: append(data, '\n'),
		Summary: map[string]any{
			"snapshotKind":  "doctor",
			"overallStatus": result.OverallStatus,
			"engine":        result.Engine,
			"summary":       result.Summary,
		},
	}, nil
}

func materializeFactorySnapshotArtifacts(dir string, deps factoryRunExecutionDeps) ([]factory.ArtifactReference, func(), error) {
	snapshotFns := []func(string) (factorySnapshotArtifact, error){
		deps.statusSnapshot,
		deps.doctorSnapshot,
	}

	artifacts := make([]factory.ArtifactReference, 0, len(snapshotFns))
	tempPaths := make([]string, 0, len(snapshotFns))
	cleanup := func() {
		for _, path := range tempPaths {
			_ = os.Remove(path)
		}
	}

	for _, snapshotFn := range snapshotFns {
		if snapshotFn == nil {
			continue
		}
		snapshot, err := snapshotFn(dir)
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("create factory snapshot artifact: %w", err)
		}
		snapshot.Name = strings.TrimSpace(snapshot.Name)
		snapshot.Path = strings.TrimSpace(snapshot.Path)
		if snapshot.Name == "" || snapshot.Path == "" || len(snapshot.Data) == 0 {
			continue
		}

		tempFile, err := os.CreateTemp("", "hal-factory-snapshot-*.json")
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("create factory snapshot temp file: %w", err)
		}
		tempPath := tempFile.Name()
		tempPaths = append(tempPaths, tempPath)
		if _, err := tempFile.Write(snapshot.Data); err != nil {
			_ = tempFile.Close()
			cleanup()
			return nil, nil, fmt.Errorf("write factory snapshot temp file: %w", err)
		}
		if err := tempFile.Close(); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("close factory snapshot temp file: %w", err)
		}

		artifacts = append(artifacts, factory.ArtifactReference{
			Name:       snapshot.Name,
			Type:       "json",
			SourcePath: tempPath,
			Path:       filepath.ToSlash(snapshot.Path),
			Summary:    snapshot.Summary,
			Warnings:   snapshot.Warnings,
		})
	}

	return artifacts, cleanup, nil
}

func materializeFactoryOutcomeArtifacts(dir string, startedAt time.Time, snapshot factoryArtifactSnapshot) ([]factory.ArtifactReference, func(), error) {
	state := factoryOutcomePipelineState(dir, startedAt, snapshot)
	return materializeFactoryOutcomeArtifactsFromState(state)
}

func materializeFactorySandboxOutcomeArtifacts(store factory.Store, record factory.RunRecord) ([]factory.ArtifactReference, func(), error) {
	state, err := factorySandboxOutcomePipelineState(store, record)
	if err != nil {
		return nil, nil, err
	}
	return materializeFactoryOutcomeArtifactsFromState(state)
}

func materializeFactoryOutcomeArtifactsFromState(state *compound.PipelineState) ([]factory.ArtifactReference, func(), error) {
	if state == nil || state.CI == nil {
		return []factory.ArtifactReference{
			missingFactoryOutcomeArtifact("pr-outcome", "factory/pr-outcome.json", "PR outcome data was unavailable"),
			missingFactoryOutcomeArtifact("ci-outcome", "factory/ci-outcome.json", "CI outcome data was unavailable"),
		}, nil, nil
	}

	artifacts := make([]factory.ArtifactReference, 0, 2)
	tempPaths := make([]string, 0, 2)
	cleanup := func() {
		for _, path := range tempPaths {
			_ = os.Remove(path)
		}
	}

	if prURL := safeFactoryPRURL(state.CI.PRURL); prURL != "" {
		artifact, tempPath, err := materializeFactoryJSONArtifact("pr-outcome", "factory/pr-outcome.json", factoryPROutcomeArtifact{
			PullRequestURL: prURL,
			Number:         state.CI.PRNumber,
			Title:          strings.TrimSpace(state.CI.PRTitle),
			HeadRef:        strings.TrimSpace(state.CI.PRHeadRef),
			BaseRef:        strings.TrimSpace(state.CI.PRBaseRef),
			Reused:         state.CI.PRReused,
			BranchName:     strings.TrimSpace(state.BranchName),
		}, map[string]any{
			"outcomeKind":    "pull_request",
			"pullRequestUrl": prURL,
		})
		if err != nil {
			cleanup()
			return nil, nil, err
		}
		tempPaths = append(tempPaths, tempPath)
		artifacts = append(artifacts, artifact)
	} else {
		artifacts = append(artifacts, missingFactoryOutcomeArtifact("pr-outcome", "factory/pr-outcome.json", "PR outcome data was unavailable"))
	}

	if strings.TrimSpace(state.CI.Status) != "" {
		artifact, tempPath, err := materializeFactoryJSONArtifact("ci-outcome", "factory/ci-outcome.json", factoryCIOutcomeArtifact{
			Status:       strings.TrimSpace(state.CI.Status),
			Reason:       strings.TrimSpace(state.CI.Reason),
			FixAttempts:  state.CI.FixAttempts,
			FixesApplied: state.CI.FixesApplied,
			BranchName:   strings.TrimSpace(state.BranchName),
		}, map[string]any{
			"outcomeKind": "ci",
			"status":      strings.TrimSpace(state.CI.Status),
		})
		if err != nil {
			cleanup()
			return nil, nil, err
		}
		tempPaths = append(tempPaths, tempPath)
		artifacts = append(artifacts, artifact)
	} else {
		artifacts = append(artifacts, missingFactoryOutcomeArtifact("ci-outcome", "factory/ci-outcome.json", "CI outcome data was unavailable"))
	}

	return artifacts, cleanup, nil
}

func factorySandboxOutcomePipelineState(store factory.Store, record factory.RunRecord) (*compound.PipelineState, error) {
	for _, artifact := range record.Artifacts {
		if strings.TrimSpace(artifact.ID) == "sandbox-auto-state" || strings.TrimSpace(artifact.Name) == "sandbox-auto-state" {
			return loadFactoryRunStoredPipelineState(store, record, artifact)
		}
	}

	autoStatePath := filepath.ToSlash(filepath.Join(template.HalDir, template.AutoStateFile))
	for _, artifact := range record.Artifacts {
		if filepath.ToSlash(strings.TrimSpace(artifact.Path)) == autoStatePath {
			return loadFactoryRunStoredPipelineState(store, record, artifact)
		}
	}
	return nil, nil
}

func loadFactoryRunStoredPipelineState(store factory.Store, record factory.RunRecord, artifact factory.ArtifactReference) (*compound.PipelineState, error) {
	if artifact.Partial || strings.TrimSpace(artifact.StoredPath) == "" {
		return nil, nil
	}
	path, err := store.ResolveArtifactPath(record.RunID, artifact.StoredPath)
	if err != nil {
		return nil, fmt.Errorf("resolve sandbox auto-state artifact: %w", err)
	}
	state, ok := loadFactoryRunPipelineState(path)
	if !ok {
		return nil, nil
	}
	return state, nil
}

func factoryOutcomePipelineState(dir string, startedAt time.Time, snapshot factoryArtifactSnapshot) *compound.PipelineState {
	autoStatePath := filepath.Join(template.HalDir, template.AutoStateFile)
	liveState, ok := loadFactoryRunPipelineState(filepath.Join(dir, autoStatePath))
	liveStateChanged := ok && factoryArtifactChangedSinceSnapshot(dir, autoStatePath, snapshot)
	if liveStateChanged && factoryPipelineStateHasOutcomeData(liveState) {
		return liveState
	}

	archived := collectFactoryRunArchivedArtifacts(dir, startedAt)
	for i := range archived.pipelineStates {
		state := &archived.pipelineStates[i]
		if factoryPipelineStateHasOutcomeData(state) {
			return state
		}
	}

	if liveStateChanged {
		return liveState
	}
	return nil
}

func factoryPipelineStateHasOutcomeData(state *compound.PipelineState) bool {
	if state == nil || state.CI == nil {
		return false
	}
	return safeFactoryPRURL(state.CI.PRURL) != "" || strings.TrimSpace(state.CI.Status) != ""
}

func storeFactoryOutcomeArtifacts(store factory.Store, record factory.RunRecord, artifacts []factory.ArtifactReference) error {
	missingArtifacts := make([]factory.ArtifactReference, 0)
	for _, artifact := range artifacts {
		artifact.ID = factoryArtifactID(artifact)
		if artifact.Partial && artifact.SourcePath == "" {
			missingArtifacts = append(missingArtifacts, artifact)
			continue
		}
		sourcePath := artifact.SourcePath
		if strings.TrimSpace(sourcePath) == "" {
			sourcePath = artifact.Path
		}
		if strings.TrimSpace(sourcePath) == "" {
			continue
		}
		if _, err := store.SaveArtifactFile(record.RunID, artifact, sourcePath); err != nil {
			return fmt.Errorf("store factory outcome artifact %q from %s: %w", artifact.Name, artifact.Path, err)
		}
	}
	if len(missingArtifacts) == 0 {
		return nil
	}

	updatedRecord, err := store.LoadRun(record.RunID)
	if err != nil {
		return fmt.Errorf("load factory run for missing outcome artifact warnings: %w", err)
	}
	for _, missing := range missingArtifacts {
		updatedRecord.Artifacts = upsertFactoryRunArtifact(updatedRecord.Artifacts, missing)
	}
	if err := store.SaveRun(updatedRecord); err != nil {
		return fmt.Errorf("record missing factory outcome artifact warnings: %w", err)
	}
	return nil
}

func materializeFactoryJSONArtifact(name, displayPath string, payload any, summary map[string]any) (factory.ArtifactReference, string, error) {
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return factory.ArtifactReference{}, "", fmt.Errorf("marshal factory outcome artifact %q: %w", name, err)
	}
	tempFile, err := os.CreateTemp("", "hal-factory-outcome-*.json")
	if err != nil {
		return factory.ArtifactReference{}, "", fmt.Errorf("create factory outcome temp file: %w", err)
	}
	tempPath := tempFile.Name()
	if _, err := tempFile.Write(append(data, '\n')); err != nil {
		_ = tempFile.Close()
		_ = os.Remove(tempPath)
		return factory.ArtifactReference{}, "", fmt.Errorf("write factory outcome temp file: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		_ = os.Remove(tempPath)
		return factory.ArtifactReference{}, "", fmt.Errorf("close factory outcome temp file: %w", err)
	}

	return factory.ArtifactReference{
		Name:       name,
		Type:       "json",
		SourcePath: tempPath,
		Path:       filepath.ToSlash(displayPath),
		Summary:    summary,
	}, tempPath, nil
}

func missingFactoryOutcomeArtifact(name, displayPath, warning string) factory.ArtifactReference {
	return factory.ArtifactReference{
		Name:    name,
		Type:    "json",
		Path:    filepath.ToSlash(displayPath),
		Partial: true,
		Summary: map[string]any{
			"collectionStatus": "missing",
		},
		Warnings: []string{warning},
	}
}

func safeFactoryPRURL(rawURL string) string {
	return safeFactoryArtifactURL(rawURL)
}

func safeFactoryArtifactURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.User != nil {
		return ""
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return ""
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	for key := range parsed.Query() {
		if factoryArtifactSecretURLQueryKey(key) {
			return ""
		}
	}
	if factoryArtifactStringContainsSecretAssignment(parsed.Fragment) {
		return ""
	}
	return parsed.String()
}

func refreshFactoryRunBranchForMode(store factory.Store, runID, dir string, req factoryRunRequest, currentBranch func(string) (string, error), now time.Time) (factory.RunRecord, error) {
	if req.Sandbox {
		record, err := store.LoadRun(runID)
		if err != nil {
			return factory.RunRecord{}, fmt.Errorf("load factory run for branch refresh: %w", err)
		}
		return *record, nil
	}
	return refreshFactoryRunBranch(store, runID, dir, currentBranch, now)
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

func newFactoryRunVerificationFailure(result *verify.Result) error {
	if result == nil {
		return fmt.Errorf("verification failed")
	}
	summary := result.Summary
	return fmt.Errorf("verification failed: %d failed, %d timed out, %d missing", summary.Failed, summary.TimedOut, summary.Missing)
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
	case factoryFailureMessageContains(message, "verification", "verify"):
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

func collectFactoryRunArtifacts(store factory.Store, dir string, req factoryRunRequest, record factory.RunRecord, snapshot factoryArtifactSnapshot, snapshots []factory.ArtifactReference) []factory.ArtifactReference {
	collector := newFactoryArtifactCollector(dir)
	archived := collectFactoryRunArchivedArtifacts(dir, record.CreatedAt)

	if markdownPath := strings.TrimSpace(req.MarkdownPath); markdownPath != "" {
		collector.addRequestedOrArchived("source-markdown", markdownPath, archived)
	}
	if reportPath := strings.TrimSpace(req.ReportPath); reportPath != "" {
		collector.addRequestedOrArchived("source-report", reportPath, archived)
	}

	halDir := filepath.Join(dir, template.HalDir)
	canonicalPRDPath := filepath.Join(template.HalDir, template.PRDFile)
	autoStatePath := filepath.Join(template.HalDir, template.AutoStateFile)
	if req.Sandbox {
		for _, artifact := range snapshots {
			collector.add(artifact)
		}
		return collector.artifacts
	}

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
	for _, artifact := range snapshots {
		collector.add(artifact)
	}

	return collector.artifacts
}

func recordFactoryRunRecordArtifact(store factory.Store, record factory.RunRecord) (factory.RunRecord, error) {
	recordPath := factoryRunRecordArtifactPath(store, record.RunID)
	if recordPath == "" {
		return record, nil
	}
	sourcePath, cleanup, err := materializeFactoryRunRecordArtifact(record)
	if err != nil {
		return factory.RunRecord{}, err
	}
	defer cleanup()
	artifact := factory.ArtifactReference{
		ID:   "factory-run-record",
		Name: "factory-run-record",
		Type: "json",
		Path: recordPath,
	}
	if _, err := store.SaveArtifactFile(record.RunID, artifact, sourcePath); err != nil {
		return factory.RunRecord{}, fmt.Errorf("store factory run record artifact: %w", err)
	}
	updatedRecord, err := store.LoadRun(record.RunID)
	if err != nil {
		return factory.RunRecord{}, fmt.Errorf("reload factory run record artifact: %w", err)
	}
	return *updatedRecord, nil
}

func materializeFactoryRunRecordArtifact(record factory.RunRecord) (string, func(), error) {
	scrubbed := scrubFactoryRunRecordForArtifact(record)
	data, err := json.MarshalIndent(scrubbed, "", "  ")
	if err != nil {
		return "", func() {}, fmt.Errorf("marshal factory run record artifact: %w", err)
	}
	tmp, err := os.CreateTemp("", "hal-factory-run-record-*.json")
	if err != nil {
		return "", func() {}, fmt.Errorf("create factory run record artifact temp file: %w", err)
	}
	cleanup := func() {
		_ = os.Remove(tmp.Name())
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("write factory run record artifact temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("close factory run record artifact temp file: %w", err)
	}
	return tmp.Name(), cleanup, nil
}

func scrubFactoryRunRecordForArtifact(record factory.RunRecord) factory.RunRecord {
	record.Artifacts = scrubFactoryArtifactReferencesForRecordArtifact(record.Artifacts)
	record.Verification = scrubFactoryVerificationRecord(record.Verification)
	return record
}

func scrubFactoryArtifactReferencesForRecordArtifact(artifacts []factory.ArtifactReference) []factory.ArtifactReference {
	if artifacts == nil {
		return nil
	}
	out := make([]factory.ArtifactReference, len(artifacts))
	for i, artifact := range artifacts {
		artifact.SourcePath = ""
		artifact.Path = sanitizeFactoryArtifactPath(artifact.Path)
		artifact.StoredPath = sanitizeFactoryArtifactPath(artifact.StoredPath)
		artifact.URL = safeFactoryArtifactURL(artifact.URL)
		artifact.Summary = sanitizeFactoryArtifactSummary(artifact.Summary)
		artifact.Warnings = sanitizeFactoryArtifactWarnings(artifact.Warnings)
		out[i] = artifact
	}
	return out
}

func scrubFactoryVerificationRecord(record *factory.VerificationRecord) *factory.VerificationRecord {
	if record == nil {
		return nil
	}
	out := *record
	if record.Artifacts != nil {
		out.Artifacts = make([]verify.ArtifactReference, len(record.Artifacts))
		for i, artifact := range record.Artifacts {
			artifact.Path = sanitizeFactoryArtifactPath(artifact.Path)
			out.Artifacts[i] = artifact
		}
	}
	return &out
}

func collectAndStoreFactoryRunArtifacts(store factory.Store, dir string, req factoryRunRequest, record factory.RunRecord, snapshot factoryArtifactSnapshot, snapshots []factory.ArtifactReference) error {
	artifacts := collectFactoryRunArtifacts(store, dir, req, record, snapshot, snapshots)
	missingArtifacts := make([]factory.ArtifactReference, 0)
	for _, artifact := range artifacts {
		if artifact.Partial && artifact.SourcePath == "" {
			artifact.ID = factoryArtifactID(artifact)
			missingArtifacts = append(missingArtifacts, artifact)
			continue
		}
		sourcePath := artifact.Path
		if artifact.SourcePath != "" {
			sourcePath = artifact.SourcePath
		}
		if sourcePath == "" {
			continue
		}
		absoluteSourcePath := sourcePath
		if !filepath.IsAbs(absoluteSourcePath) {
			absoluteSourcePath = filepath.Join(dir, sourcePath)
		}
		if factoryArtifactFileExists(absoluteSourcePath) {
			artifact.ID = factoryArtifactID(artifact)
			if _, err := store.SaveArtifactFile(record.RunID, artifact, absoluteSourcePath); err != nil {
				return fmt.Errorf("store factory artifact %q from %s: %w", artifact.Name, artifact.Path, err)
			}
			continue
		}

		missing := artifact
		missing.ID = factoryArtifactID(missing)
		missing.Partial = true
		missing.Warnings = append(missing.Warnings, factoryMissingArtifactWarning("optional artifact not found", artifact.Path))
		missing.Summary = mergeFactoryArtifactSummary(missing.Summary, map[string]any{
			"collectionStatus": "missing",
		})
		missingArtifacts = append(missingArtifacts, missing)
	}
	if len(missingArtifacts) > 0 {
		updatedRecord, err := store.LoadRun(record.RunID)
		if err != nil {
			return fmt.Errorf("load factory run for missing artifact warnings: %w", err)
		}
		for _, missing := range missingArtifacts {
			updatedRecord.Artifacts = upsertFactoryRunArtifact(updatedRecord.Artifacts, missing)
		}
		if err := store.SaveRun(updatedRecord); err != nil {
			return fmt.Errorf("record missing factory artifact warnings: %w", err)
		}
	}
	return nil
}

func collectAndStoreFactoryVerificationArtifacts(store factory.Store, dir, runID string, artifacts []verify.ArtifactReference) error {
	missingArtifacts := make([]factory.ArtifactReference, 0)
	for _, artifact := range artifacts {
		path := strings.TrimSpace(artifact.Path)
		if path == "" {
			continue
		}
		nameParts := []string{"verification"}
		if checkID := strings.TrimSpace(artifact.CheckID); checkID != "" {
			nameParts = append(nameParts, sanitizeFactoryArtifactPathComponent(checkID))
		}
		if kind := strings.TrimSpace(artifact.Kind); kind != "" {
			nameParts = append(nameParts, sanitizeFactoryArtifactPathComponent(kind))
		}
		ref := factory.ArtifactReference{
			Name: strings.Join(nameParts, "-"),
			Type: factoryArtifactTypeForPath(path),
			Path: filepath.Clean(path),
			Summary: map[string]any{
				"checkId": artifact.CheckID,
				"kind":    artifact.Kind,
			},
		}
		ref.ID = factoryArtifactID(ref)
		sourcePath := path
		if !filepath.IsAbs(sourcePath) {
			sourcePath = filepath.Join(dir, sourcePath)
		}
		if !factoryArtifactFileExists(sourcePath) {
			missing := ref
			missing.Partial = true
			missing.Warnings = append(missing.Warnings, factoryMissingArtifactWarning("verification artifact not found", ref.Path))
			missing.Summary = mergeFactoryArtifactSummary(missing.Summary, map[string]any{
				"collectionStatus": "missing",
			})
			missingArtifacts = append(missingArtifacts, missing)
			continue
		}
		if _, err := store.SaveArtifactFile(runID, ref, sourcePath); err != nil {
			return fmt.Errorf("store factory verification artifact %q from %s: %w", ref.Name, ref.Path, err)
		}
	}
	if len(missingArtifacts) > 0 {
		updatedRecord, err := store.LoadRun(runID)
		if err != nil {
			return fmt.Errorf("load factory run for missing verification artifact warnings: %w", err)
		}
		for _, missing := range missingArtifacts {
			updatedRecord.Artifacts = upsertFactoryRunArtifact(updatedRecord.Artifacts, missing)
		}
		if err := store.SaveRun(updatedRecord); err != nil {
			return fmt.Errorf("record missing factory verification artifact warnings: %w", err)
		}
	}
	return nil
}

func collectAndStoreFactorySandboxArtifacts(ctx context.Context, store factory.Store, dir string, record factory.RunRecord, deps factoryRunExecutionDeps) error {
	if record.ExecutorMode != factory.ExecutorModeSandbox {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	requests := deps.sandboxRequests(dir, record)
	if len(requests) == 0 {
		return nil
	}
	copier := deps.sandboxCopier
	if copier == nil {
		if strings.TrimSpace(record.RepoPath) == "" {
			return nil
		}
		defaultCopier, err := newFactorySandboxArtifactCopier(dir, record)
		if err != nil {
			return fmt.Errorf("create sandbox artifact copier: %w", err)
		}
		copier = defaultCopier
	}
	if _, err := factory.CollectSandboxArtifacts(ctx, store, record.RunID, copier, requests); err != nil {
		return fmt.Errorf("collect sandbox factory artifacts: %w", err)
	}
	return nil
}

func defaultFactorySandboxArtifactRequests(_ string, record factory.RunRecord) []factory.SandboxArtifactRequest {
	summary := map[string]any{
		"executorMode": factory.ExecutorModeSandbox,
	}
	if sandboxName := strings.TrimSpace(record.SandboxName); sandboxName != "" {
		summary["sandboxName"] = sandboxName
	}

	requests := []factory.SandboxArtifactRequest{
		{
			ID:         "sandbox-prd",
			Name:       "sandbox-prd",
			Type:       "json",
			RemotePath: filepath.ToSlash(filepath.Join(template.HalDir, template.PRDFile)),
			Path:       filepath.ToSlash(filepath.Join(template.HalDir, template.PRDFile)),
			Optional:   true,
			Summary:    summary,
		},
		{
			ID:         "sandbox-auto-state",
			Name:       "sandbox-auto-state",
			Type:       "json",
			RemotePath: filepath.ToSlash(filepath.Join(template.HalDir, template.AutoStateFile)),
			Path:       filepath.ToSlash(filepath.Join(template.HalDir, template.AutoStateFile)),
			Optional:   true,
			Summary:    summary,
		},
		{
			ID:         "sandbox-progress",
			Name:       "sandbox-progress",
			Type:       "text",
			RemotePath: filepath.ToSlash(filepath.Join(template.HalDir, template.ProgressFile)),
			Path:       filepath.ToSlash(filepath.Join(template.HalDir, template.ProgressFile)),
			Optional:   true,
			Summary:    summary,
		},
		{
			ID:         "sandbox-reports",
			Name:       "sandbox-reports",
			Type:       "directory",
			RemotePath: filepath.ToSlash(filepath.Join(template.HalDir, "reports")),
			Path:       filepath.ToSlash(filepath.Join(template.HalDir, "reports")),
			Directory:  true,
			Optional:   true,
			Summary:    summary,
		},
	}
	if sourcePath := strings.TrimSpace(record.Source.Path); sourcePath != "" {
		requests = append([]factory.SandboxArtifactRequest{{
			ID:         "sandbox-source",
			Name:       "sandbox-source",
			Type:       factoryArtifactTypeForPath(sourcePath),
			RemotePath: filepath.ToSlash(sourcePath),
			Path:       filepath.ToSlash(sourcePath),
			Optional:   true,
			Summary:    summary,
		}}, requests...)
	}
	return requests
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
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
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

func (c *factoryArtifactCollector) addRequestedOrArchived(name, path string, archived factoryArchivedArtifacts) bool {
	if c.addExistingOrArchived(name, path, archived) {
		return true
	}
	return c.addReference(name, path)
}

func (c *factoryArtifactCollector) addArchived(name, path string, archived factoryArchivedArtifacts) bool {
	archivedPath := archived.find(path)
	if archivedPath == "" {
		return false
	}
	return c.addExisting(name, archivedPath)
}

func (c *factoryArtifactCollector) addReference(name, path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	c.add(factory.ArtifactReference{
		Name: name,
		Type: factoryArtifactTypeForPath(path),
		Path: c.displayPath(path),
	})
	return true
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
	if _, err := os.Stat(reportsDir); err != nil {
		return nil
	}

	type reportFile struct {
		name    string
		path    string
		modTime time.Time
	}
	reportFiles := make([]reportFile, 0)
	_ = filepath.WalkDir(reportsDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			if entry.IsDir() && path != reportsDir {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		if !startedAt.IsZero() && info.ModTime().Before(startedAt) {
			return nil
		}
		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return nil
		}
		reportFiles = append(reportFiles, reportFile{
			name:    name,
			path:    relPath,
			modTime: info.ModTime(),
		})
		return nil
	})

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
			if err != nil || !info.Mode().IsRegular() {
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

func factoryArtifactID(artifact factory.ArtifactReference) string {
	if id := strings.TrimSpace(artifact.ID); id != "" {
		return id
	}
	source := strings.TrimSpace(artifact.Path)
	if source == "" {
		source = artifact.Name
	}
	id := sanitizeFactoryArtifactID(source)
	if strings.TrimSpace(artifact.Path) == "" {
		return id
	}
	return appendFactoryArtifactIDHash(id, source)
}

func sanitizeFactoryArtifactID(value string) string {
	value = filepath.ToSlash(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "./")
	value = strings.Trim(value, "/")
	id := sanitizeFactoryArtifactPathComponent(value)
	if id == "" {
		return "artifact"
	}
	return id
}

func sanitizeFactoryArtifactPathComponent(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	lastHyphen := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' {
			builder.WriteRune(r)
			lastHyphen = false
			continue
		}
		if !lastHyphen {
			builder.WriteByte('-')
			lastHyphen = true
		}
	}
	return strings.Trim(builder.String(), "-")
}

func appendFactoryArtifactIDHash(id, source string) string {
	source = filepath.ToSlash(strings.TrimSpace(source))
	source = strings.TrimPrefix(source, "./")
	source = strings.Trim(source, "/")
	sum := sha256.Sum256([]byte(source))
	hash := fmt.Sprintf("%x", sum[:6])
	ext := filepath.Ext(id)
	if ext != "" && len(id) > len(ext) {
		return strings.TrimSuffix(id, ext) + "-" + hash + ext
	}
	return id + "-" + hash
}

func mergeFactoryArtifactSummary(existing map[string]any, values map[string]any) map[string]any {
	if len(existing) == 0 && len(values) == 0 {
		return nil
	}
	merged := make(map[string]any, len(existing)+len(values))
	for key, value := range existing {
		merged[key] = value
	}
	for key, value := range values {
		merged[key] = value
	}
	return merged
}

func upsertFactoryRunArtifact(artifacts []factory.ArtifactReference, artifact factory.ArtifactReference) []factory.ArtifactReference {
	for i := range artifacts {
		if artifact.ID != "" && artifacts[i].ID == artifact.ID {
			artifacts[i] = artifact
			return artifacts
		}
		if artifact.Path != "" && artifacts[i].Path == artifact.Path {
			artifacts[i] = artifact
			return artifacts
		}
		if artifact.StoredPath != "" && artifacts[i].StoredPath == artifact.StoredPath {
			artifacts[i] = artifact
			return artifacts
		}
	}
	return append(artifacts, artifact)
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
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
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

func recordFactoryRunVerificationResult(store factory.Store, runID string, now time.Time, result verify.Result) error {
	return appendFactoryRunTimelineEvent(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypeVerificationResult,
		Summary:   factoryRunVerificationSummary(result),
		Metadata: map[string]any{
			"status":        result.Status,
			"total":         result.Summary.Total,
			"passed":        result.Summary.Passed,
			"failed":        result.Summary.Failed,
			"timedOut":      result.Summary.TimedOut,
			"missing":       result.Summary.Missing,
			"skipped":       result.Summary.Skipped,
			"warnings":      result.Summary.Warnings,
			"artifactCount": len(result.Artifacts),
		},
	})
}

func factoryRunVerificationSummary(result verify.Result) string {
	switch result.Status {
	case verify.StatusPass:
		return "Verification passed"
	case verify.StatusWarn:
		return "Verification completed with warnings"
	case verify.StatusFail:
		return "Verification failed"
	default:
		return "Verification completed"
	}
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

func recordFactoryRunVerificationFailed(store factory.Store, runID string, now time.Time, verificationErr error) error {
	return appendFactoryRunTimelineEvent(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypeStepEnded,
		Summary:   "Verification failed",
		Metadata: map[string]any{
			"step":   "verify",
			"status": factory.RunStatusFailed,
			"error":  verificationErr.Error(),
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
	autoReq.WorkDir = strings.TrimSpace(req.WorkDir)
	if autoReq.WorkDir == "" {
		autoReq.WorkDir = strings.TrimSpace(req.Record.RepoPath)
	}
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

	err := runInFactoryRunDir(req.WorkDir, func() error {
		return runAuto(cmd, req.Args)
	})
	if progressWriter != nil {
		if flushErr := progressWriter.Flush(); flushErr != nil {
			return errors.Join(err, flushErr)
		}
	}
	return err
}

func runInFactoryRunDir(dir string, fn func() error) error {
	if fn == nil {
		return nil
	}
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return fn()
	}

	previousDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}
	if err := os.Chdir(dir); err != nil {
		return fmt.Errorf("change to factory run directory %q: %w", dir, err)
	}

	runErr := fn()
	if restoreErr := os.Chdir(previousDir); restoreErr != nil {
		return errors.Join(runErr, fmt.Errorf("restore working directory %q: %w", previousDir, restoreErr))
	}
	return runErr
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
	sandboxName := factoryRunSandboxNameFlag
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
		if cmd.Flags().Lookup("sandbox-name") != nil {
			value, err := cmd.Flags().GetString("sandbox-name")
			if err != nil {
				return factoryRunRequest{}, err
			}
			sandboxName = value
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

	req, err := parseFactoryRunRequest(args, reportPath, baseBranch, sandboxName, jsonMode, sandboxMode)
	if err != nil {
		return factoryRunRequest{}, exitWithCode(cmd, ExitCodeValidation, err)
	}
	return req, nil
}

func parseFactoryRunRequest(args []string, reportPath, baseBranch, sandboxName string, jsonMode bool, sandboxMode bool) (factoryRunRequest, error) {
	if len(args) > 1 {
		return factoryRunRequest{}, fmt.Errorf("accepts at most 1 arg(s), received %d", len(args))
	}
	if len(args) == 1 && strings.TrimSpace(reportPath) != "" {
		return factoryRunRequest{}, fmt.Errorf("--report cannot be used with a positional PRD markdown path")
	}
	if sandboxMode && strings.TrimSpace(baseBranch) == "" {
		return factoryRunRequest{}, fmt.Errorf("--base is required when --sandbox is set")
	}
	if !sandboxMode && strings.TrimSpace(sandboxName) != "" {
		return factoryRunRequest{}, fmt.Errorf("--sandbox-name requires --sandbox")
	}

	req := factoryRunRequest{
		ReportPath:  reportPath,
		BaseBranch:  baseBranch,
		SandboxName: sandboxName,
		Sandbox:     sandboxMode,
		JSON:        jsonMode,
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

func runFactoryArtifacts(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	jsonMode := factoryArtifactsJSONFlag

	if cmd != nil {
		out = cmd.OutOrStdout()
		if cmd.Flags().Lookup("json") != nil {
			value, err := cmd.Flags().GetBool("json")
			if err != nil {
				return err
			}
			jsonMode = value
		}
	}

	return runFactoryArtifactsWithDeps(out, args[0], jsonMode, defaultFactoryArtifactsDeps)
}

func runFactoryArtifactsWithDeps(out io.Writer, runID string, jsonMode bool, deps factoryArtifactsDeps) error {
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

	if jsonMode {
		return renderFactoryArtifactsJSON(out, *record)
	}
	renderFactoryArtifactsTable(out, *record)
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
		Run:             newFactoryStatusRun(record),
		Timeline:        events,
	}
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal factory status: %w", err)
	}
	fmt.Fprintln(out, string(data))
	return nil
}

func newFactoryStatusRun(record factory.RunRecord) FactoryStatusRun {
	return FactoryStatusRun{
		RunID:        record.RunID,
		Status:       record.Status,
		ExecutorMode: record.ExecutorMode,
		Source:       record.Source,
		RepoPath:     record.RepoPath,
		RepoRemote:   record.RepoRemote,
		BranchName:   record.BranchName,
		BaseBranch:   record.BaseBranch,
		SandboxName:  record.SandboxName,
		Sandbox:      record.Sandbox,
		CurrentStep:  record.CurrentStep,
		CreatedAt:    record.CreatedAt,
		UpdatedAt:    record.UpdatedAt,
		FinishedAt:   record.FinishedAt,
		Artifacts:    newFactoryStatusArtifactSummaries(record.Artifacts),
		Verification: scrubFactoryVerificationRecord(record.Verification),
		Failure:      record.Failure,
	}
}

func renderFactoryArtifactsJSON(out io.Writer, record factory.RunRecord) error {
	resp := newFactoryArtifactsResponse(record)
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal factory artifacts: %w", err)
	}
	fmt.Fprintln(out, string(data))
	return nil
}

func newFactoryArtifactsResponse(record factory.RunRecord) FactoryArtifactsResponse {
	artifacts := newFactoryArtifactSummaries(record.Artifacts)
	warningSet := map[string]bool{}
	partialCount := 0
	warningCount := 0

	for _, entry := range artifacts {
		if entry.Partial {
			partialCount++
		}
		warningCount += len(entry.Warnings)
		for _, warning := range entry.Warnings {
			if warning != "" {
				warningSet[warning] = true
			}
		}
	}

	warnings := make([]string, 0, len(warningSet))
	for warning := range warningSet {
		warnings = append(warnings, warning)
	}
	sort.Strings(warnings)

	return FactoryArtifactsResponse{
		ContractVersion: FactoryArtifactsContractVersion,
		RunID:           record.RunID,
		Artifacts:       artifacts,
		Warnings:        warnings,
		Summary: FactoryArtifactsSummary{
			Total:    len(artifacts),
			Partial:  partialCount,
			Warnings: warningCount,
		},
	}
}

func newFactoryArtifactSummaries(artifacts []factory.ArtifactReference) []FactoryArtifactSummary {
	return newFactoryArtifactSummariesWithOptions(artifacts, false)
}

func newFactoryStatusArtifactSummaries(artifacts []factory.ArtifactReference) []FactoryArtifactSummary {
	return newFactoryArtifactSummariesWithOptions(artifacts, true)
}

func newFactoryArtifactSummariesWithOptions(artifacts []factory.ArtifactReference, includeURL bool) []FactoryArtifactSummary {
	summaries := make([]FactoryArtifactSummary, 0, len(artifacts))
	for _, artifact := range artifacts {
		entry := FactoryArtifactSummary{
			ID:         strings.TrimSpace(artifact.ID),
			Name:       strings.TrimSpace(artifact.Name),
			Type:       strings.TrimSpace(artifact.Type),
			Path:       sanitizeFactoryArtifactPath(artifact.Path),
			StoredPath: sanitizeFactoryArtifactPath(artifact.StoredPath),
			SizeBytes:  artifact.SizeBytes,
			CreatedAt:  artifact.CreatedAt,
			Summary:    sanitizeFactoryArtifactSummary(artifact.Summary),
			Warnings:   sanitizeFactoryArtifactWarnings(artifact.Warnings),
			Partial:    artifact.Partial,
		}
		if includeURL {
			entry.URL = safeFactoryArtifactURL(artifact.URL)
		}
		if entry.Path == "" && entry.StoredPath == "" && artifact.URL != "" {
			if entry.URL == "" {
				entry.Path = "[redacted]"
			}
		}
		summaries = append(summaries, entry)
	}
	return summaries
}

func sanitizeFactoryArtifactPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if strings.Contains(path, "://") {
		if safeURL := safeFactoryArtifactURL(path); safeURL != "" {
			return safeURL
		}
		return "[redacted]"
	}
	if factoryArtifactStringContainsSecretAssignment(path) {
		return "[redacted]"
	}
	cleanPath := filepath.Clean(path)
	if factoryArtifactLooksLikeWindowsAbsolutePath(path) || factoryArtifactLooksLikeWindowsAbsolutePath(cleanPath) {
		return "[redacted]"
	}
	if filepath.IsAbs(cleanPath) {
		base := filepath.Base(cleanPath)
		if base == "" || base == "." || base == string(os.PathSeparator) {
			return "[redacted]"
		}
		return filepath.ToSlash(base)
	}
	if factoryArtifactPathIsParentRelative(cleanPath) {
		return "[redacted]"
	}
	return filepath.ToSlash(cleanPath)
}

func factoryArtifactPathIsParentRelative(value string) bool {
	value = strings.TrimSpace(value)
	value = filepath.ToSlash(value)
	value = strings.ReplaceAll(value, `\`, "/")
	value = pathpkg.Clean(value)
	if value == ".." || strings.HasPrefix(value, "../") {
		return true
	}
	return false
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

func renderFactoryArtifactsTable(out io.Writer, record factory.RunRecord) {
	fmt.Fprintf(out, "Run ID: %s\n", record.RunID)
	if len(record.Artifacts) == 0 {
		fmt.Fprintf(out, "No artifacts collected for factory run %s.\n", record.RunID)
		return
	}

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tTYPE\tPATH\tSTORED PATH\tSUMMARY\tWARNINGS")
	for _, artifact := range newFactoryStatusArtifactSummaries(record.Artifacts) {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			artifact.Name,
			artifact.Type,
			factoryArtifactSummaryDisplayPath(artifact),
			sanitizeFactoryArtifactPath(artifact.StoredPath),
			formatFactoryArtifactSummary(artifact.Summary),
			formatFactoryArtifactSummaryWarnings(artifact.Warnings, artifact.Partial),
		)
	}
	_ = w.Flush()
}

func factoryArtifactDisplayPath(artifact factory.ArtifactReference) string {
	if path := strings.TrimSpace(artifact.Path); path != "" {
		return path
	}
	if path := strings.TrimSpace(artifact.StoredPath); path != "" {
		return path
	}
	if path := strings.TrimSpace(artifact.URL); path != "" {
		return path
	}
	return "-"
}

func factoryArtifactSummaryDisplayPath(artifact FactoryArtifactSummary) string {
	if path := strings.TrimSpace(artifact.Path); path != "" {
		return path
	}
	if path := sanitizeFactoryArtifactPath(artifact.StoredPath); path != "" {
		return path
	}
	if path := strings.TrimSpace(artifact.URL); path != "" {
		return path
	}
	return "-"
}

func formatFactoryArtifactSummary(summary map[string]any) string {
	if len(summary) == 0 {
		return "-"
	}

	keys := make([]string, 0, len(summary))
	for key := range summary {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		value, err := json.Marshal(summary[key])
		if err != nil {
			parts = append(parts, fmt.Sprintf("%s=%v", key, summary[key]))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s", key, string(value)))
	}
	return strings.Join(parts, ", ")
}

func formatFactoryArtifactWarnings(artifact factory.ArtifactReference) string {
	return formatFactoryArtifactSummaryWarnings(artifact.Warnings, artifact.Partial)
}

func formatFactoryArtifactSummaryWarnings(warnings []string, partial bool) string {
	warnings = append([]string(nil), warnings...)
	if partial && len(warnings) == 0 {
		warnings = append(warnings, "partial")
	}
	if len(warnings) == 0 {
		return "-"
	}
	return strings.Join(warnings, "; ")
}

func factoryMissingArtifactWarning(message, artifactPath string) string {
	displayPath := sanitizeFactoryArtifactPath(artifactPath)
	if displayPath == "" {
		return message
	}
	return fmt.Sprintf("%s: %s", message, displayPath)
}

func sanitizeFactoryArtifactSummary(summary map[string]any) map[string]any {
	if len(summary) == 0 {
		return nil
	}
	safe := make(map[string]any, len(summary))
	for key, value := range summary {
		safe[key] = sanitizeFactoryArtifactValue(key, value)
	}
	return safe
}

func sanitizeFactoryArtifactWarnings(warnings []string) []string {
	if len(warnings) == 0 {
		return nil
	}
	safe := make([]string, 0, len(warnings))
	for _, warning := range warnings {
		warning = strings.TrimSpace(warning)
		if warning == "" {
			continue
		}
		if factoryArtifactStringNeedsRedaction(warning) {
			warning = "[redacted]"
		}
		safe = append(safe, warning)
	}
	if len(safe) == 0 {
		return nil
	}
	return safe
}

func sanitizeFactoryArtifactValue(key string, value any) any {
	if factoryArtifactSecretKey(key) {
		return "[redacted]"
	}
	switch v := value.(type) {
	case nil:
		return nil
	case string:
		if factoryArtifactStringNeedsRedaction(v) {
			return "[redacted]"
		}
		return v
	case []any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, sanitizeFactoryArtifactValue("", item))
		}
		return out
	case map[string]any:
		return sanitizeFactoryArtifactSummary(v)
	case map[string]string:
		out := make(map[string]any, len(v))
		for itemKey, itemValue := range v {
			out[itemKey] = sanitizeFactoryArtifactValue(itemKey, itemValue)
		}
		return out
	default:
		if normalized, ok := normalizeFactoryArtifactCompositeValue(value); ok {
			return sanitizeFactoryArtifactValue(key, normalized)
		}
		return value
	}
}

func normalizeFactoryArtifactCompositeValue(value any) (any, bool) {
	if value == nil {
		return nil, false
	}
	rv := reflect.ValueOf(value)
	for rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return nil, false
		}
		rv = rv.Elem()
	}
	switch rv.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.Struct:
	default:
		return nil, false
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, false
	}
	var normalized any
	if err := json.Unmarshal(data, &normalized); err != nil {
		return nil, false
	}
	return normalized, true
}

func factoryArtifactSecretKey(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	if key == "" {
		return false
	}
	secretFragments := []string{
		"token",
		"secret",
		"password",
		"passwd",
		"credential",
		"private_key",
		"private-key",
		"api_key",
		"api-key",
		"access_key",
		"access-key",
		"auth",
	}
	for _, fragment := range secretFragments {
		if strings.Contains(key, fragment) {
			return true
		}
	}
	return key == "key" || strings.HasSuffix(key, "_key") || strings.HasSuffix(key, "-key")
}

func factoryArtifactSecretURLQueryKey(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	if factoryArtifactSecretKey(key) {
		return true
	}
	switch key {
	case "signature", "sig", "x-amz-signature", "x-goog-signature", "x-ms-signature":
		return true
	default:
		return false
	}
}

func factoryArtifactStringNeedsRedaction(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if net.ParseIP(strings.Trim(value, "[]")) != nil {
		return true
	}
	if host, _, err := net.SplitHostPort(value); err == nil && net.ParseIP(strings.Trim(host, "[]")) != nil {
		return true
	}
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err == nil {
			if parsed.User != nil {
				return true
			}
			if host := strings.TrimSpace(parsed.Hostname()); host != "" && net.ParseIP(host) != nil {
				return true
			}
			for key := range parsed.Query() {
				if factoryArtifactSecretURLQueryKey(key) {
					return true
				}
			}
			if factoryArtifactStringContainsSecretAssignment(parsed.Fragment) {
				return true
			}
		}
	}
	if factoryArtifactStringContainsAbsolutePath(value) {
		return true
	}
	if factoryArtifactStringContainsParentRelativePath(value) {
		return true
	}
	if factoryArtifactStringContainsUnsafeURL(value) {
		return true
	}
	if factoryArtifactStringContainsSecretAssignment(value) {
		return true
	}
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '/' || r == ',' || r == ';' || r == '=' || r == '(' || r == ')' || r == '[' || r == ']'
	})
	for _, field := range fields {
		if net.ParseIP(strings.Trim(field, "[]")) != nil {
			return true
		}
	}
	return false
}

func factoryArtifactStringContainsParentRelativePath(value string) bool {
	for _, field := range factoryArtifactRedactionFields(value) {
		if factoryArtifactFieldIsParentRelativePath(field) {
			return true
		}
		if strings.Contains(field, "://") {
			continue
		}
		for _, sep := range []string{"=", ":"} {
			if idx := strings.Index(field, sep); idx >= 0 && idx+1 < len(field) {
				if factoryArtifactFieldIsParentRelativePath(field[idx+1:]) {
					return true
				}
			}
		}
	}
	return false
}

func factoryArtifactFieldIsParentRelativePath(value string) bool {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, "\"'<>[](){}.,;")
	if value == "" {
		return false
	}
	return factoryArtifactPathIsParentRelative(value)
}

func factoryArtifactStringContainsUnsafeURL(value string) bool {
	for _, field := range factoryArtifactRedactionFields(value) {
		field = strings.TrimSpace(field)
		field = strings.Trim(field, "\"'<>[](){}.,;")
		if !strings.Contains(field, "://") {
			continue
		}
		if safeFactoryArtifactURL(field) == "" {
			return true
		}
	}
	return false
}

func factoryArtifactStringContainsAbsolutePath(value string) bool {
	for _, field := range factoryArtifactRedactionFields(value) {
		if factoryArtifactFieldIsAbsolutePath(field) {
			return true
		}
		if strings.Contains(field, "://") {
			continue
		}
		for _, sep := range []string{"=", ":"} {
			if idx := strings.Index(field, sep); idx >= 0 && idx+1 < len(field) {
				if factoryArtifactFieldIsAbsolutePath(field[idx+1:]) {
					return true
				}
			}
		}
	}
	return false
}

func factoryArtifactFieldIsAbsolutePath(value string) bool {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, "\"'<>[](){}.,;")
	if value == "" {
		return false
	}
	if filepath.IsAbs(value) {
		return true
	}
	return factoryArtifactLooksLikeWindowsAbsolutePath(value)
}

func factoryArtifactLooksLikeWindowsAbsolutePath(value string) bool {
	if len(value) >= 3 {
		drive := value[0]
		if ((drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z')) && value[1] == ':' && (value[2] == '\\' || value[2] == '/') {
			return true
		}
	}
	return strings.HasPrefix(value, `\\`) || strings.HasPrefix(value, `//`)
}

func factoryArtifactStringContainsSecretAssignment(value string) bool {
	fields := factoryArtifactRedactionFields(value)
	for i, field := range fields {
		field = strings.TrimSpace(field)
		field = strings.Trim(field, "\"'<>[](){}.,;")
		if field == "" {
			continue
		}
		if idx := strings.IndexAny(field, "=:"); idx > 0 && factoryArtifactSecretKey(field[:idx]) {
			return true
		}
		if !factoryArtifactSecretKey(field) || i+1 >= len(fields) {
			continue
		}
		next := strings.TrimSpace(fields[i+1])
		if next == "=" || next == ":" || strings.HasPrefix(next, "=") || strings.HasPrefix(next, ":") {
			return true
		}
	}
	return false
}

func factoryArtifactRedactionFields(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', ',', ';', '"', '\'', '<', '>', '(', ')', '[', ']', '{', '}', '?', '&':
			return true
		default:
			return false
		}
	})
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
