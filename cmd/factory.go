package cmd

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/doctor"
	"github.com/jywlabs/hal/internal/engine"
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
	FactoryLogsContractVersion      = "factory-logs-v1"
)

const factorySandboxArtifactMissingSentinel = "__HAL_FACTORY_ARTIFACT_MISSING__"

var factoryListJSONFlag bool
var factoryStatusJSONFlag bool
var factoryArtifactsJSONFlag bool
var factoryLogsJSONFlag bool
var factoryRunReportFlag string
var factoryRunBaseFlag string
var factoryRunSecretEnvFlags []string
var factoryRunJSONFlag bool
var factoryRunSandboxFlag bool
var factoryOpenExecFlag bool
var factoryOpenJSONFlag bool

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
  hal factory logs <run-id>
  hal factory open <run-id>
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
workspace can be checked out deterministically. Use --secret-env to declare
required environment variables that should be resolved only for this run. Use
--sandbox for remote sandbox-backed execution, and --json for machine-readable
factory-run-v1 output.`,
	Example: `  hal factory run .hal/prd-feature.md
  hal factory run --report .hal/reports/analysis.md
  hal factory run .hal/prd-feature.md --secret-env GITHUB_TOKEN
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

var factoryLogsCmd = &cobra.Command{
	Use:   "logs <run-id>",
	Short: "Inspect stored factory run logs",
	Args:  exactArgsValidation(1),
	Long: `Inspect stored stdout, stderr, or summarized output chunks for one
factory run from the global factory store.

The default output is ordered human-readable log text with stream and source
metadata. Use --json for machine-readable output following the factory-logs-v1
contract. Log text is sanitized before display.`,
	Example: `  hal factory logs run-20260620-001
  hal factory logs run-20260620-001 --json`,
	RunE: runFactoryLogs,
}

func init() {
	factoryRunCmd.Flags().StringVar(&factoryRunReportFlag, "report", "", "Start from an analysis report path")
	factoryRunCmd.Flags().StringVar(&factoryRunBaseFlag, "base", "", "Target base branch for follow-up review or CI")
	factoryRunCmd.Flags().StringArrayVar(&factoryRunSecretEnvFlags, "secret-env", nil, "Required environment variable secret for the run (repeatable)")
	factoryRunCmd.Flags().BoolVar(&factoryRunSandboxFlag, "sandbox", false, "Run the factory executor in a managed sandbox")
	factoryRunCmd.Flags().BoolVar(&factoryRunJSONFlag, "json", false, "Output machine-readable JSON (factory-run-v1 contract)")
	factoryListCmd.Flags().BoolVar(&factoryListJSONFlag, "json", false, "Output machine-readable JSON (factory-list-v1 contract)")
	factoryStatusCmd.Flags().BoolVar(&factoryStatusJSONFlag, "json", false, "Output machine-readable JSON (factory-status-v1 contract)")
	factoryArtifactsCmd.Flags().BoolVar(&factoryArtifactsJSONFlag, "json", false, "Output machine-readable JSON (factory-artifacts-v1 contract)")
	factoryLogsCmd.Flags().BoolVar(&factoryLogsJSONFlag, "json", false, "Output machine-readable JSON (factory-logs-v1 contract)")
	factoryOpenCmd.Flags().BoolVar(&factoryOpenExecFlag, "exec", false, "Execute the suggested inspection or resume command")
	factoryOpenCmd.Flags().BoolVar(&factoryOpenJSONFlag, "json", false, "Output machine-readable JSON (factory-open-v1 contract)")
	configureFactoryTriggerCommand()
	configureFactoryQueueCommands()
	factoryCmd.AddCommand(factoryRunCmd)
	factoryCmd.AddCommand(factoryListCmd)
	factoryCmd.AddCommand(factoryStatusCmd)
	factoryCmd.AddCommand(factoryLogsCmd)
	factoryCmd.AddCommand(factoryOpenCmd)
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

type factoryLogsDeps struct {
	defaultStore func() (factory.Store, error)
}

var defaultFactoryLogsDeps = factoryLogsDeps{
	defaultStore: factory.DefaultStore,
}

type factoryRunDeps struct {
	defaultStore           func() (factory.Store, error)
	newRunID               func() (string, error)
	now                    func() time.Time
	workingDir             func() (string, error)
	currentBranch          func(string) (string, error)
	repoRemote             func(string) (string, error)
	lookupEnv              func(string) (string, bool)
	loadPolicy             func(string) (*factory.FactoryPolicy, error)
	loadEngine             func(string) (string, error)
	loadEngineConfig       func(string, string) *engine.EngineConfig
	runPipeline            func(context.Context, factoryRunPipelineRequest) error
	runSandbox             func(context.Context, factorySandboxExecutorRequest) error
	loadVerify             func(string) (*verify.Config, error)
	runVerify              func(context.Context, *verify.Config) (*verify.Result, error)
	loadSandbox            func(string) (*sandbox.SandboxState, error)
	resolveProvider        func(string, string) (sandbox.Provider, error)
	runProviderExec        func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error
	runProviderExecWithEnv func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, map[string]string, io.Writer) error
	cleanupSandbox         func(context.Context, factorySandboxCleanupRequest) error
	statusSnapshot         func(string) (factorySnapshotArtifact, error)
	doctorSnapshot         func(string) (factorySnapshotArtifact, error)
	sandboxCopier          factory.SandboxArtifactCopier
	sandboxRequests        func(string, factory.RunRecord) []factory.SandboxArtifactRequest
}

type factoryRunPipelineRequest struct {
	RunID          string
	Request        factoryRunRequest
	Record         factory.RunRecord
	Store          factory.Store
	Engine         string
	AttemptPolicy  autoFactoryAttemptPolicy
	SkipCI         bool
	Now            func() time.Time
	RecordProgress func(factoryRunProgressEvent) error
}

var defaultFactoryRunDeps = factoryRunDeps{
	defaultStore:     factory.DefaultStore,
	newRunID:         sandbox.NewV7,
	now:              time.Now,
	workingDir:       os.Getwd,
	currentBranch:    compound.CurrentBranchOptionalInDir,
	repoRemote:       readGitRemoteOptionalInDir,
	lookupEnv:        os.LookupEnv,
	loadPolicy:       factory.LoadPolicyConfig,
	loadEngine:       compound.LoadDefaultEngine,
	loadEngineConfig: compound.LoadEngineConfig,
	runPipeline:      runFactoryRunPipeline,
	runSandbox: func(ctx context.Context, req factorySandboxExecutorRequest) error {
		return runFactorySandboxExecutorWithDeps(ctx, req, factorySandboxExecutorDeps{})
	},
	loadVerify:             verify.LoadConfig,
	runVerify:              verify.Run,
	loadSandbox:            sandbox.LoadActiveInstance,
	resolveProvider:        resolveProviderWithFallback,
	runProviderExec:        runFactorySandboxProviderExec,
	runProviderExecWithEnv: runFactorySandboxProviderExecWithEnv,
	cleanupSandbox:         cleanupFactorySandbox,
	statusSnapshot:         defaultFactoryStatusSnapshot,
	doctorSnapshot:         defaultFactoryDoctorSnapshot,
}

type factoryRunRequest struct {
	MarkdownPath string
	ReportPath   string
	BaseBranch   string
	Sandbox      bool
	JSON         bool
	Secrets      []factory.RunSecretInput

	ResolvedSecrets []factory.ResolvedRunSecret
}

type factoryRunAutoRequest struct {
	Args          []string
	ReportPath    string
	BaseBranch    string
	Engine        string
	AttemptPolicy autoFactoryAttemptPolicy
	SkipCI        bool
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

type factoryRunExecutionDeps struct {
	now         func() time.Time
	runPipeline func(context.Context, factoryRunPipelineRequest) error
}

type factoryRunExecutionResult struct {
	Record factory.RunRecord
	Render bool
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

// FactoryLogsResponse is the machine-readable JSON output for
// hal factory logs <run-id> --json.
type FactoryLogsResponse struct {
	ContractVersion string             `json:"contractVersion"`
	RunID           string             `json:"runId"`
	Chunks          []factory.LogChunk `json:"chunks"`
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
	RunID           string                           `json:"runId"`
	Status          string                           `json:"status"`
	ExecutorMode    string                           `json:"executorMode,omitempty"`
	Engine          string                           `json:"engine,omitempty"`
	Source          factory.SourceMetadata           `json:"source"`
	RepoPath        string                           `json:"repoPath"`
	RepoRemote      string                           `json:"repoRemote"`
	BranchName      string                           `json:"branchName"`
	BaseBranch      string                           `json:"baseBranch"`
	Policy          *factory.FactoryPolicy           `json:"policy,omitempty"`
	PolicyDecisions []factory.PolicyDecisionMetadata `json:"policyDecisions,omitempty"`
	SandboxName     string                           `json:"sandboxName,omitempty"`
	Sandbox         *factory.SandboxMetadata         `json:"sandbox,omitempty"`
	CurrentStep     string                           `json:"currentStep"`
	CreatedAt       time.Time                        `json:"createdAt"`
	UpdatedAt       time.Time                        `json:"updatedAt"`
	FinishedAt      *time.Time                       `json:"finishedAt,omitempty"`
	Secrets         []factory.RunSecretMetadata      `json:"secrets,omitempty"`
	Artifacts       []FactoryArtifactSummary         `json:"artifacts,omitempty"`
	Verification    *factory.VerificationRecord      `json:"verification,omitempty"`
	Telemetry       *factory.RunTelemetry            `json:"telemetry,omitempty"`
	Failure         *factory.FailureSummary          `json:"failure,omitempty"`
	Handoff         *factory.HandoffSummary          `json:"handoff,omitempty"`
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
// artifact. It intentionally omits sourcePath and url because those fields can
// contain workspace-local paths or uncontracted network addresses.
type FactoryArtifactSummary struct {
	ID         string         `json:"id,omitempty"`
	Name       string         `json:"name"`
	Type       string         `json:"type"`
	Path       string         `json:"path,omitempty"`
	StoredPath string         `json:"storedPath,omitempty"`
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
	Telemetry     *factory.RunTelemetry   `json:"telemetry,omitempty"`
	Failure       *factory.FailureSummary `json:"failure,omitempty"`
}

func validateFactoryRunArgs(cmd *cobra.Command, args []string) error {
	if len(args) > 1 {
		return maxArgsValidation(1)(cmd, args)
	}

	reportPath := ""
	if cmd != nil && cmd.Flags().Lookup("report") != nil {
		value, err := cmd.Flags().GetString("report")
		if err != nil {
			return err
		}
		reportPath = value
	}

	if _, err := parseFactoryRunRequest(args, reportPath, "", false, false); err != nil {
		return exitWithCode(cmd, ExitCodeValidation, err)
	}
	return nil
}

func runFactoryRun(cmd *cobra.Command, args []string) error {
	req, err := factoryRunRequestFromCommand(cmd, args)
	if err != nil {
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

	return runFactoryRunWithDeps(ctx, ".", req, out, defaultFactoryRunDeps)
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
	record, err := newFactoryRunRecord(dir, req, deps)
	if err != nil {
		return err
	}
	initialRedactor := factory.NewRunSecretRedactor(resolveFactoryRunRedactionSecrets(req.Secrets, deps.lookupEnv))
	safeInitialRecord := redactFactoryRunRecordForStorage(record, initialRedactor)
	if err := createFactoryRunRecord(store, safeInitialRecord); err != nil {
		return err
	}
	if err := recordFactoryRunStarted(store, safeInitialRecord); err != nil {
		return err
	}
	creationPolicy, err := loadFactoryRunPolicy(dir, deps)
	if err != nil {
		return failFactoryRunCreationWithRedactor(store, record, out, req.JSON, deps.now(), fmt.Errorf("load factory policy: %w", err), nil, initialRedactor)
	}
	record, err = persistFactoryRunPolicySnapshotWithRedactor(store, record, creationPolicy, initialRedactor)
	if err != nil {
		return failFactoryRunCreationWithRedactor(store, record, out, req.JSON, deps.now(), err, nil, initialRedactor)
	}
	engineName, err := resolveFactoryRunEngine(dir, deps)
	if err != nil {
		return failFactoryRunCreationWithRedactor(store, record, out, req.JSON, deps.now(), err, nil, initialRedactor)
	}
	record, err = persistFactoryRunEngineSnapshotWithRedactor(store, record, engineName, initialRedactor)
	if err != nil {
		return failFactoryRunCreationWithRedactor(store, record, out, req.JSON, deps.now(), err, nil, initialRedactor)
	}
	if err := enforceFactoryRunCreationPolicyWithRedactor(store, record, out, req.JSON, deps, creationPolicy, engineName, initialRedactor); err != nil {
		return err
	}

	result, execErr := executeFactoryRun(ctx, dir, req, out, store, record, deps, creationPolicy, engineName)
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

func executeFactoryRun(ctx context.Context, dir string, req factoryRunRequest, out io.Writer, store factory.Store, record factory.RunRecord, deps factoryRunDeps, policy factory.FactoryPolicy, engineName string) (factoryRunExecutionResult, error) {
	if out == nil {
		out = io.Discard
	}
	deps = normalizeFactoryRunDeps(deps)
	if deps.runPipeline == nil {
		return factoryRunExecutionResult{Record: record}, fmt.Errorf("factory run pipeline dependency is required")
	}
	if record.Policy == nil {
		var err error
		record, err = persistFactoryRunPolicySnapshot(store, record, policy)
		if err != nil {
			return factoryRunExecutionResult{Record: record}, err
		}
	}

	req, record, err := resolveFactoryRunExecutionSecrets(req, record, deps)
	redactor := factory.NewRunSecretRedactor(req.ResolvedSecrets)
	if err != nil {
		return failFactoryRunSetup(store, record, deps.now(), err, redactor)
	}
	if req.Sandbox && strings.TrimSpace(req.BaseBranch) == "" {
		return failFactoryRunSetup(store, record, deps.now(), fmt.Errorf("--base is required when --sandbox is set"), redactor)
	}

	runningRecord, err := markFactoryRunInProgressWithRedactor(store, record, deps.now(), redactor)
	if err != nil {
		return factoryRunExecutionResult{Record: record}, err
	}
	if err := recordFactoryRunPipelineStarted(store, runningRecord); err != nil {
		return factoryRunExecutionResult{Record: runningRecord}, err
	}
	if err := recordFactoryRunPreExecutionPolicyDecisions(store, runningRecord.RunID, deps.now, policy); err != nil {
		return factoryRunExecutionResult{Record: runningRecord}, err
	}

	pipelineReq := factoryRunPipelineRequest{
		RunID:         runningRecord.RunID,
		Request:       req,
		Record:        runningRecord,
		Store:         store,
		Engine:        engineName,
		AttemptPolicy: autoFactoryAttemptPolicyFromFactoryPolicy(policy),
		SkipCI:        factoryPolicySkipsCI(policy),
		Now:           deps.now,
		RecordProgress: func(event factoryRunProgressEvent) error {
			return recordFactoryRunProgressWithRedactor(store, runningRecord.RunID, deps.now(), event, redactor)
		},
	}
	artifactSnapshot := snapshotFactoryRunArtifacts(dir)
	sandboxArtifactsCollected := false
	runErr := error(nil)
	if req.Sandbox {
		remoteOutput := out
		if req.JSON {
			remoteOutput = io.Discard
		}
		remoteAuto := factoryRunAutoRequestFromFactoryRequest(req)
		remoteAuto.Engine = engineName
		remoteAuto.AttemptPolicy = autoFactoryAttemptPolicyFromFactoryPolicy(policy)
		remoteAuto.SkipCI = factoryPolicySkipsCI(policy)
		runErr = deps.runSandbox(ctx, factorySandboxExecutorRequest{
			ProjectDir:          dir,
			RunRecord:           runningRecord,
			ResolvedSecrets:     req.ResolvedSecrets,
			RemoteAuto:          remoteAuto,
			RemoteOutput:        remoteOutput,
			DeferSuccessCleanup: factoryRunDefersSandboxSuccessCleanup(policy),
			BeforeCleanup: func(ctx context.Context, record factory.RunRecord) error {
				if sandboxArtifactsCollected {
					return nil
				}
				if err := collectAndStoreFactorySandboxArtifacts(ctx, store, dir, req, record, deps); err != nil {
					return err
				}
				sandboxArtifactsCollected = true
				return nil
			},
		})
	} else {
		runErr = deps.runPipeline(ctx, pipelineReq)
	}
	if runErr != nil {
		failedAt := deps.now()
		failedRecord := runningRecord
		var recordErrs []error
		if artifactRecord, artifactErr := recordFactoryRunArtifacts(ctx, store, runningRecord.RunID, dir, req, artifactSnapshot, failedAt, deps, !sandboxArtifactsCollected, redactor); artifactErr != nil {
			recordErrs = append(recordErrs, fmt.Errorf("record factory artifacts: %w", artifactErr))
		} else {
			failedRecord = artifactRecord
		}
		if decision, ok := factoryPolicyDecisionFromAttemptLimit(runErr); ok {
			if eventErr := recordFactoryPolicyDecision(store, runningRecord.RunID, failedAt, decision); eventErr != nil {
				recordErrs = append(recordErrs, fmt.Errorf("record factory policy decision: %w", eventErr))
			}
		}

		recordErr := runErr
		if req.Sandbox {
			recordErr = factorySandboxPipelineRecordError(failedRecord, runErr)
		}
		failedRecord, failureErr := markFactoryRunFailedWithRedactor(store, failedRecord, failedAt, recordErr, redactor)
		if failureErr != nil {
			recordErrs = append(recordErrs, failureErr)
		}
		if eventErr := recordFactoryRunPipelineFailedWithRedactor(store, runningRecord.RunID, failedAt, recordErr, redactor); eventErr != nil {
			recordErrs = append(recordErrs, fmt.Errorf("record factory failure event: %w", eventErr))
		}
		if failedRecord.Failure != nil {
			if eventErr := recordFactoryRunFailureClassified(store, failedRecord.RunID, failedAt, *failedRecord.Failure); eventErr != nil {
				recordErrs = append(recordErrs, fmt.Errorf("record factory failure classification event: %w", eventErr))
			}
		}
		if artifactRecord, artifactErr := recordFactoryRunRecordArtifactWithRedactor(store, failedRecord, redactor); artifactErr != nil {
			recordErrs = append(recordErrs, artifactErr)
		} else {
			failedRecord = artifactRecord
		}
		runErr = redactFactoryRunError(runErr, redactor)
		if len(recordErrs) > 0 {
			return factoryRunExecutionResult{Record: failedRecord}, errors.Join(append([]error{runErr}, recordErrs...)...)
		}
		return factoryRunExecutionResult{Record: failedRecord, Render: true}, runErr
	}

	pipelineCompletedAt := deps.now()
	if err := recordFactoryRunPipelineSucceeded(store, runningRecord.RunID, pipelineCompletedAt); err != nil {
		return factoryRunExecutionResult{Record: runningRecord}, err
	}
	completedRecord, err := recordFactoryRunArtifacts(ctx, store, runningRecord.RunID, dir, req, artifactSnapshot, pipelineCompletedAt, deps, !sandboxArtifactsCollected, redactor)
	if err != nil {
		return failFactoryRunAfterArtifactCollectionFailure(ctx, store, dir, req, out, runningRecord, deps, policy, err)
	}
	completedRecord, completedAt, err := recordFactoryRunVerification(ctx, store, completedRecord, dir, deps, policy, req.ResolvedSecrets, redactor)
	if err != nil {
		failedRecord, failureErr := markFactoryRunFailedWithRedactor(store, completedRecord, completedAt, err, redactor)
		var recordErrs []error
		if failureErr != nil {
			recordErrs = append(recordErrs, failureErr)
		}
		if eventErr := recordFactoryRunVerificationFailedWithRedactor(store, failedRecord.RunID, completedAt, err, redactor); eventErr != nil {
			recordErrs = append(recordErrs, fmt.Errorf("record factory verification failure event: %w", eventErr))
		}
		if failedRecord.Failure != nil {
			if eventErr := recordFactoryRunFailureClassified(store, failedRecord.RunID, completedAt, *failedRecord.Failure); eventErr != nil {
				recordErrs = append(recordErrs, fmt.Errorf("record factory failure classification event: %w", eventErr))
			}
		}
		if cleanupRecord, cleanedUp, cleanupErr := cleanupFactoryRunSandboxAfterFailedRun(ctx, store, dir, req, out, failedRecord, deps, policy, "verification failure"); cleanedUp {
			failedRecord = cleanupRecord
			if cleanupErr != nil {
				recordErrs = append(recordErrs, cleanupErr)
			}
		} else if cleanupErr != nil {
			recordErrs = append(recordErrs, cleanupErr)
		}
		if artifactRecord, artifactErr := recordFactoryRunRecordArtifactWithRedactor(store, failedRecord, redactor); artifactErr != nil {
			recordErrs = append(recordErrs, artifactErr)
		} else {
			failedRecord = artifactRecord
		}
		err = redactFactoryRunError(err, redactor)
		if len(recordErrs) > 0 {
			return factoryRunExecutionResult{Record: failedRecord}, errors.Join(append([]error{err}, recordErrs...)...)
		}
		return factoryRunExecutionResult{Record: failedRecord, Render: true}, err
	}
	completedRecord, cleanedUp, err := cleanupFactoryRunSandboxAfterVerifiedSuccess(ctx, store, dir, req, out, completedRecord, deps, policy)
	if err != nil {
		failedAt := deps.now()
		failedRecord, failureErr := markFactoryRunFailedWithRedactor(store, completedRecord, failedAt, err, redactor)
		var recordErrs []error
		if failureErr != nil {
			recordErrs = append(recordErrs, failureErr)
		}
		if eventErr := recordFactoryRunPipelineFailedWithRedactor(store, failedRecord.RunID, failedAt, err, redactor); eventErr != nil {
			recordErrs = append(recordErrs, fmt.Errorf("record factory cleanup failure event: %w", eventErr))
		}
		if failedRecord.Failure != nil {
			if eventErr := recordFactoryRunFailureClassified(store, failedRecord.RunID, failedAt, *failedRecord.Failure); eventErr != nil {
				recordErrs = append(recordErrs, fmt.Errorf("record factory failure classification event: %w", eventErr))
			}
		}
		if artifactRecord, artifactErr := recordFactoryRunRecordArtifactWithRedactor(store, failedRecord, redactor); artifactErr != nil {
			recordErrs = append(recordErrs, artifactErr)
		} else {
			failedRecord = artifactRecord
		}
		err = redactFactoryRunError(err, redactor)
		if len(recordErrs) > 0 {
			return factoryRunExecutionResult{Record: failedRecord}, errors.Join(append([]error{err}, recordErrs...)...)
		}
		return factoryRunExecutionResult{Record: failedRecord, Render: true}, err
	}
	finishedAt := completedAt
	if cleanedUp {
		finishedAt = deps.now()
	}
	completedRecord, err = markFactoryRunSucceededWithRedactor(store, completedRecord, finishedAt, redactor)
	if err != nil {
		return factoryRunExecutionResult{Record: completedRecord}, err
	}
	completedRecord, err = recordFactoryRunRecordArtifactWithRedactor(store, completedRecord, redactor)
	if err != nil {
		return factoryRunExecutionResult{Record: completedRecord}, err
	}
	return factoryRunExecutionResult{Record: completedRecord, Render: true}, nil
}

func normalizeFactoryRunExecutionDeps(deps factoryRunExecutionDeps) factoryRunExecutionDeps {
	if deps.now == nil {
		deps.now = defaultFactoryRunDeps.now
	}
	if deps.runPipeline == nil {
		deps.runPipeline = defaultFactoryRunDeps.runPipeline
	}
	return deps
}

func normalizeFactoryRunDeps(deps factoryRunDeps) factoryRunDeps {
	customRunProviderExec := deps.runProviderExec != nil
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
	if deps.loadPolicy == nil {
		deps.loadPolicy = defaultFactoryRunDeps.loadPolicy
	}
	if deps.loadEngine == nil {
		deps.loadEngine = defaultFactoryRunDeps.loadEngine
	}
	if deps.loadEngineConfig == nil {
		deps.loadEngineConfig = defaultFactoryRunDeps.loadEngineConfig
	}
	if deps.lookupEnv == nil {
		deps.lookupEnv = defaultFactoryRunDeps.lookupEnv
	}
	if deps.runPipeline == nil {
		deps.runPipeline = defaultFactoryRunDeps.runPipeline
	}
	if deps.runSandbox == nil {
		deps.runSandbox = defaultFactoryRunDeps.runSandbox
	}
	if deps.loadVerify == nil {
		deps.loadVerify = defaultFactoryRunDeps.loadVerify
	}
	if deps.runVerify == nil {
		deps.runVerify = defaultFactoryRunDeps.runVerify
	}
	if deps.loadSandbox == nil {
		deps.loadSandbox = defaultFactoryRunDeps.loadSandbox
	}
	if deps.resolveProvider == nil {
		deps.resolveProvider = defaultFactoryRunDeps.resolveProvider
	}
	if deps.runProviderExec == nil {
		deps.runProviderExec = defaultFactoryRunDeps.runProviderExec
	}
	if deps.runProviderExecWithEnv == nil {
		if customRunProviderExec {
			runProviderExec := deps.runProviderExec
			deps.runProviderExecWithEnv = func(ctx context.Context, provider sandbox.Provider, info *sandbox.ConnectInfo, args []string, _ map[string]string, out io.Writer) error {
				return runProviderExec(ctx, provider, info, args, out)
			}
		} else {
			deps.runProviderExecWithEnv = defaultFactoryRunDeps.runProviderExecWithEnv
		}
	}
	if deps.cleanupSandbox == nil {
		deps.cleanupSandbox = defaultFactoryRunDeps.cleanupSandbox
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

func resolveFactoryRunExecutionSecrets(req factoryRunRequest, record factory.RunRecord, deps factoryRunDeps) (factoryRunRequest, factory.RunRecord, error) {
	resolved, metadata, err := factory.ResolveRunSecrets(req.Secrets, deps.lookupEnv)
	req.ResolvedSecrets = resolved
	if err != nil {
		record.Secrets = factoryRunSecretMetadataWithResolvedPrefix(req.Secrets, metadata)
		record = sanitizeFactoryRunRecordCredentialedRemote(record)
		return req, record, err
	}
	record.Secrets = metadata
	return req, record, nil
}

func factoryRunSecretMetadataWithResolvedPrefix(inputs []factory.RunSecretInput, resolved []factory.RunSecretMetadata) []factory.RunSecretMetadata {
	metadata := factoryRunSecretMetadataFromInputs(inputs)
	for i, secret := range resolved {
		if i >= len(metadata) {
			metadata = append(metadata, secret)
			continue
		}
		metadata[i] = secret
	}
	return metadata
}

func failFactoryRunSetup(store factory.Store, record factory.RunRecord, now time.Time, setupErr error, redactor factory.RunSecretRedactor) (factoryRunExecutionResult, error) {
	if setupErr == nil {
		setupErr = fmt.Errorf("factory run setup failed")
	}
	validationErr := exitWithCode(nil, ExitCodeValidation, setupErr)
	safeValidationErr := redactFactoryRunError(validationErr, redactor)
	record.CurrentStep = "setup"
	failedRecord, failureErr := markFactoryRunFailedWithRedactor(store, record, now, validationErr, redactor)
	var recordErrs []error
	if failureErr != nil {
		recordErrs = append(recordErrs, failureErr)
	}
	if eventErr := recordFactoryRunSetupFailedWithRedactor(store, record.RunID, now, validationErr, redactor); eventErr != nil {
		recordErrs = append(recordErrs, fmt.Errorf("record factory setup failure event: %w", eventErr))
	}
	if failedRecord.Failure != nil {
		if eventErr := recordFactoryRunFailureClassified(store, failedRecord.RunID, now, *failedRecord.Failure); eventErr != nil {
			recordErrs = append(recordErrs, fmt.Errorf("record factory failure classification event: %w", eventErr))
		}
	}
	if len(recordErrs) > 0 {
		return factoryRunExecutionResult{Record: failedRecord}, errors.Join(append([]error{safeValidationErr}, recordErrs...)...)
	}
	return factoryRunExecutionResult{Record: failedRecord, Render: true}, safeValidationErr
}

func newFactoryRunRecord(dir string, req factoryRunRequest, deps factoryRunDeps) (factory.RunRecord, error) {
	runID, err := deps.newRunID()
	if err != nil {
		return factory.RunRecord{}, fmt.Errorf("create factory run ID: %w", err)
	}
	now := deps.now().UTC()
	repoPath, err := deps.workingDir()
	if err != nil {
		return factory.RunRecord{}, fmt.Errorf("resolve repository path: %w", err)
	}
	branchName, err := deps.currentBranch(dir)
	if err != nil {
		return factory.RunRecord{}, fmt.Errorf("resolve current branch: %w", err)
	}
	repoRemote, err := deps.repoRemote(dir)
	if err != nil {
		return factory.RunRecord{}, fmt.Errorf("resolve repository remote: %w", err)
	}

	return factory.RunRecord{
		RunID:        runID,
		Status:       factory.RunStatusPending,
		ExecutorMode: factoryExecutorModeFromRequest(req),
		Source:       factoryRunSourceFromRequest(req),
		RepoPath:     repoPath,
		RepoRemote:   repoRemote,
		BranchName:   branchName,
		BaseBranch:   strings.TrimSpace(req.BaseBranch),
		CurrentStep:  factory.RunStatusPending,
		Secrets:      factoryRunSecretMetadataFromInputs(req.Secrets),
		CreatedAt:    now,
		UpdatedAt:    now,
		Telemetry:    factoryRunEngineTelemetry(dir, deps),
	}, nil
}

type factoryPolicyRejectionError struct {
	policyField string
	decision    string
	outcome     string
	reason      string
}

func (e *factoryPolicyRejectionError) Error() string {
	return fmt.Sprintf("factory policy rejected run creation: %s %s", e.policyField, e.reason)
}

func (e *factoryPolicyRejectionError) policyDecisionMetadata() factory.PolicyDecisionMetadata {
	return factory.PolicyDecisionMetadata{
		PolicyField: e.policyField,
		Decision:    e.decision,
		Outcome:     e.outcome,
		Reason:      e.reason,
	}
}

func loadFactoryRunPolicy(dir string, deps factoryRunDeps) (factory.FactoryPolicy, error) {
	if deps.loadPolicy == nil {
		deps.loadPolicy = defaultFactoryRunDeps.loadPolicy
	}
	policy, err := deps.loadPolicy(dir)
	if err != nil {
		return factory.FactoryPolicy{}, err
	}
	if policy == nil {
		return factory.DefaultFactoryPolicy(), nil
	}
	return *policy, nil
}

func persistFactoryRunPolicySnapshot(store factory.Store, record factory.RunRecord, policy factory.FactoryPolicy) (factory.RunRecord, error) {
	return persistFactoryRunPolicySnapshotWithRedactor(store, record, policy, factory.RunSecretRedactor{})
}

func persistFactoryRunPolicySnapshotWithRedactor(store factory.Store, record factory.RunRecord, policy factory.FactoryPolicy, redactor factory.RunSecretRedactor) (factory.RunRecord, error) {
	snapshot := policy
	if policy.AllowedEngines != nil {
		snapshot.AllowedEngines = append([]string(nil), policy.AllowedEngines...)
	}
	record.Policy = &snapshot
	safeRecord := redactFactoryRunRecordForStorage(record, redactor)
	if err := store.SaveRun(&safeRecord); err != nil {
		return factory.RunRecord{}, fmt.Errorf("persist factory policy snapshot: %w", err)
	}
	return record, nil
}

func factoryPolicySnapshotFromRecord(record *factory.RunRecord) *factory.FactoryPolicy {
	if record == nil || record.Policy == nil {
		return nil
	}
	snapshot := *record.Policy
	if record.Policy.AllowedEngines != nil {
		snapshot.AllowedEngines = append([]string(nil), record.Policy.AllowedEngines...)
	}
	return &snapshot
}

func persistFactoryRunEngineSnapshot(store factory.Store, record factory.RunRecord, engineName string) (factory.RunRecord, error) {
	return persistFactoryRunEngineSnapshotWithRedactor(store, record, engineName, factory.RunSecretRedactor{})
}

func persistFactoryRunEngineSnapshotWithRedactor(store factory.Store, record factory.RunRecord, engineName string, redactor factory.RunSecretRedactor) (factory.RunRecord, error) {
	record.Engine = normalizeFactoryRunEngineName(engineName)
	safeRecord := redactFactoryRunRecordForStorage(record, redactor)
	if err := store.SaveRun(&safeRecord); err != nil {
		return factory.RunRecord{}, fmt.Errorf("persist factory engine snapshot: %w", err)
	}
	return record, nil
}

func resolveFactoryRunEngine(dir string, deps factoryRunDeps) (string, error) {
	if deps.loadEngine == nil {
		deps.loadEngine = defaultFactoryRunDeps.loadEngine
	}
	engineName, err := deps.loadEngine(dir)
	if err != nil {
		return "", fmt.Errorf("load factory engine policy input: %w", err)
	}
	return normalizeFactoryRunEngineName(engineName), nil
}

func normalizeFactoryRunEngineName(engineName string) string {
	return strings.ToLower(strings.TrimSpace(engineName))
}

func factoryRunEngineSnapshotFromRecord(record *factory.RunRecord) string {
	if record == nil {
		return ""
	}
	return normalizeFactoryRunEngineName(record.Engine)
}

func enforceFactoryRunCreationPolicy(store factory.Store, record factory.RunRecord, out io.Writer, jsonMode bool, deps factoryRunDeps, policy factory.FactoryPolicy, engineName string) error {
	return enforceFactoryRunCreationPolicyWithRedactor(store, record, out, jsonMode, deps, policy, engineName, factory.RunSecretRedactor{})
}

func enforceFactoryRunCreationPolicyWithRedactor(store factory.Store, record factory.RunRecord, out io.Writer, jsonMode bool, deps factoryRunDeps, policy factory.FactoryPolicy, engineName string, redactor factory.RunSecretRedactor) error {
	rejection := factoryRunCreationPolicyRejection(policy, record.ExecutorMode, engineName)
	if rejection == nil {
		return nil
	}

	decision := rejection.policyDecisionMetadata()
	return failFactoryRunCreationWithRedactor(store, record, out, jsonMode, deps.now(), rejection, &decision, redactor)
}

func factoryRunCreationPolicyRejection(policy factory.FactoryPolicy, executorMode, engineName string) *factoryPolicyRejectionError {
	executorMode = strings.TrimSpace(executorMode)
	if policy.SandboxRequired && executorMode != factory.ExecutorModeSandbox {
		reason := fmt.Sprintf("requires sandbox executor (requested %s)", executorMode)
		if executorMode == "" {
			reason = "requires sandbox executor"
		}
		return &factoryPolicyRejectionError{
			policyField: "factory.policy.sandboxRequired",
			decision:    factory.PolicyDecisionRejectedExecution,
			outcome:     factory.PolicyOutcomeRejected,
			reason:      reason,
		}
	}

	engineName = strings.ToLower(strings.TrimSpace(engineName))
	if !factoryPolicyAllowsEngine(policy, engineName) {
		reason := fmt.Sprintf("does not allow engine %q", engineName)
		if engineName == "" {
			reason = "does not allow an empty engine"
		}
		return &factoryPolicyRejectionError{
			policyField: "factory.policy.allowedEngines",
			decision:    factory.PolicyDecisionRejectedExecution,
			outcome:     factory.PolicyOutcomeRejected,
			reason:      reason,
		}
	}

	return nil
}

func factoryPolicyAllowsEngine(policy factory.FactoryPolicy, engineName string) bool {
	engineName = strings.ToLower(strings.TrimSpace(engineName))
	if engineName == "" {
		return false
	}
	for _, allowed := range policy.AllowedEngines {
		if strings.ToLower(strings.TrimSpace(allowed)) == engineName {
			return true
		}
	}
	return false
}

func recordFactoryRunPreExecutionPolicyDecisions(store factory.Store, runID string, now func() time.Time, policy factory.FactoryPolicy) error {
	if now == nil {
		now = time.Now
	}
	var errs []error
	if !policy.PRCreationAllowed {
		decision := factory.PolicyDecisionMetadata{
			PolicyField: "factory.policy.prCreationAllowed",
			Decision:    factory.PolicyDecisionBlockedGate,
			Outcome:     factory.PolicyOutcomeBlocked,
			Reason:      "PR creation disabled; CI/PR step skipped",
		}
		if err := recordFactoryPolicyDecision(store, runID, now(), decision); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func factoryPolicySkipsCI(policy factory.FactoryPolicy) bool {
	return !policy.PRCreationAllowed
}

func factoryRunDefersSandboxSuccessCleanup(policy factory.FactoryPolicy) bool {
	switch strings.TrimSpace(policy.CleanupBehavior) {
	case factory.CleanupBehaviorOnSuccess, factory.CleanupBehaviorAlways:
		return true
	default:
		return false
	}
}

func factoryRunCleansSandboxAfterFailure(policy factory.FactoryPolicy) bool {
	return strings.TrimSpace(policy.CleanupBehavior) == factory.CleanupBehaviorAlways
}

func cleanupFactoryRunSandboxAfterVerifiedSuccess(ctx context.Context, store factory.Store, dir string, req factoryRunRequest, out io.Writer, record factory.RunRecord, deps factoryRunDeps, policy factory.FactoryPolicy) (factory.RunRecord, bool, error) {
	return cleanupFactoryRunDeferredSandbox(ctx, store, dir, req, out, record, deps, policy, "success")
}

func cleanupFactoryRunSandboxAfterFailedRun(ctx context.Context, store factory.Store, dir string, req factoryRunRequest, out io.Writer, record factory.RunRecord, deps factoryRunDeps, policy factory.FactoryPolicy, cleanupContext string) (factory.RunRecord, bool, error) {
	if !factoryRunCleansSandboxAfterFailure(policy) {
		return record, false, nil
	}
	return cleanupFactoryRunDeferredSandbox(ctx, store, dir, req, out, record, deps, policy, cleanupContext)
}

func cleanupFactoryRunDeferredSandbox(ctx context.Context, store factory.Store, dir string, req factoryRunRequest, out io.Writer, record factory.RunRecord, deps factoryRunDeps, policy factory.FactoryPolicy, cleanupContext string) (factory.RunRecord, bool, error) {
	if !req.Sandbox || !factoryRunDefersSandboxSuccessCleanup(policy) {
		return record, false, nil
	}
	cleanupContext = strings.TrimSpace(cleanupContext)
	if cleanupContext == "" {
		cleanupContext = "deferred"
	}
	name := strings.TrimSpace(record.SandboxName)
	if name == "" && record.Sandbox != nil {
		name = strings.TrimSpace(record.Sandbox.Name)
	}
	if name == "" {
		return record, false, nil
	}
	target, err := deps.loadSandbox(name)
	if err != nil {
		return record, false, fmt.Errorf("load factory sandbox for %s cleanup %q: %w", cleanupContext, name, err)
	}
	if target == nil {
		return record, false, nil
	}
	provider, err := deps.resolveProvider(dir, target.Provider)
	if err != nil {
		return record, false, fmt.Errorf("resolve sandbox provider %q for %s cleanup: %w", target.Provider, cleanupContext, err)
	}
	cleanupOut := out
	if req.JSON {
		cleanupOut = io.Discard
	}
	if deps.sandboxCopier == nil {
		if artifactErr := collectAndStoreFactorySandboxArtifactsWithProviderExec(ctx, store, dir, req, record, deps, target, provider); artifactErr != nil {
			if !factoryRunCleansSandboxAfterFailure(policy) {
				return record, false, artifactErr
			}
			cleanupErr := deps.cleanupSandbox(ctx, factorySandboxCleanupRequest{
				Target:   target,
				Provider: provider,
				Out:      cleanupOut,
			})
			if cleanupErr != nil {
				return record, false, errors.Join(artifactErr, fmt.Errorf("cleanup factory sandbox after %s: %w", cleanupContext, cleanupErr))
			}
			secretRedactor := factory.NewRunSecretRedactor(req.ResolvedSecrets)
			if err := recordFactorySandboxCleanedUp(store, factorySandboxExecutorDeps{
				now:     deps.now,
				saveRun: saveFactorySandboxRunRecord,
			}, &record, target, secretRedactor); err != nil {
				return record, true, errors.Join(artifactErr, err)
			}
			return record, true, artifactErr
		}
	}
	if err := deps.cleanupSandbox(ctx, factorySandboxCleanupRequest{
		Target:   target,
		Provider: provider,
		Out:      cleanupOut,
	}); err != nil {
		return record, false, fmt.Errorf("cleanup factory sandbox after %s: %w", cleanupContext, err)
	}
	secretRedactor := factory.NewRunSecretRedactor(req.ResolvedSecrets)
	if err := recordFactorySandboxCleanedUp(store, factorySandboxExecutorDeps{
		now:     deps.now,
		saveRun: saveFactorySandboxRunRecord,
	}, &record, target, secretRedactor); err != nil {
		return record, false, err
	}
	return record, true, nil
}

func collectAndStoreFactorySandboxArtifactsWithProviderExec(ctx context.Context, store factory.Store, dir string, req factoryRunRequest, record factory.RunRecord, deps factoryRunDeps, target *sandbox.SandboxState, provider sandbox.Provider) error {
	requests := deps.sandboxRequests(dir, record)
	if len(requests) == 0 {
		return nil
	}
	var err error
	requests, err = factorySandboxRemoteWorkspaceArtifactRequests(record, requests)
	if err != nil {
		return err
	}
	copier := factoryProviderExecSandboxArtifactCopier{
		provider:        provider,
		connectInfo:     sandbox.ConnectInfoFromState(target),
		runProviderExec: deps.runProviderExec,
	}
	redactor := factory.NewRunSecretRedactor(req.ResolvedSecrets)
	if _, err := factory.CollectSandboxArtifactsWithRedactor(ctx, store, record.RunID, &copier, requests, redactor); err != nil {
		return fmt.Errorf("collect sandbox factory artifacts before cleanup: %w", err)
	}
	return nil
}

func factorySandboxRemoteWorkspaceArtifactRequests(record factory.RunRecord, requests []factory.SandboxArtifactRequest) ([]factory.SandboxArtifactRequest, error) {
	workspaceDir := strings.TrimSpace(factorySandboxRemoteWorkspaceDir(record))
	normalized := make([]factory.SandboxArtifactRequest, 0, len(requests))
	for _, request := range requests {
		remotePath := strings.TrimSpace(request.RemotePath)
		if remotePath != "" && !path.IsAbs(remotePath) {
			if workspaceDir == "" {
				return nil, errFactorySandboxWorkspaceRequired
			}
			remotePath = path.Join(filepath.ToSlash(workspaceDir), filepath.ToSlash(remotePath))
		}
		request.RemotePath = remotePath
		normalized = append(normalized, request)
	}
	return normalized, nil
}

func failFactoryRunAfterArtifactCollectionFailure(ctx context.Context, store factory.Store, dir string, req factoryRunRequest, out io.Writer, runningRecord factory.RunRecord, deps factoryRunDeps, policy factory.FactoryPolicy, artifactErr error) (factoryRunExecutionResult, error) {
	redactor := factory.NewRunSecretRedactor(req.ResolvedSecrets)
	var recordErrs []error
	failedRecord := runningRecord
	if currentRecord, err := store.LoadRun(runningRecord.RunID); err != nil {
		recordErrs = append(recordErrs, fmt.Errorf("load factory run for artifact failure: %w", err))
	} else if currentRecord != nil {
		failedRecord = *currentRecord
	}
	failedRecord.CurrentStep = factory.RunDurationStepArtifactCollect

	failedAt := deps.now()
	failedRecord, failureErr := markFactoryRunFailedWithRedactor(store, failedRecord, failedAt, artifactErr, redactor)
	if failureErr != nil {
		recordErrs = append(recordErrs, failureErr)
	}
	if eventErr := recordFactoryRunArtifactCollectionFailedWithRedactor(store, failedRecord.RunID, failedAt, artifactErr, redactor); eventErr != nil {
		recordErrs = append(recordErrs, fmt.Errorf("record factory artifact collection failure event: %w", eventErr))
	}
	if failedRecord.Failure != nil {
		if eventErr := recordFactoryRunFailureClassified(store, failedRecord.RunID, failedAt, *failedRecord.Failure); eventErr != nil {
			recordErrs = append(recordErrs, fmt.Errorf("record factory failure classification event: %w", eventErr))
		}
	}
	if cleanupRecord, cleanedUp, cleanupErr := cleanupFactoryRunSandboxAfterFailedRun(ctx, store, dir, req, out, failedRecord, deps, policy, "artifact collection failure"); cleanedUp {
		failedRecord = cleanupRecord
		if cleanupErr != nil {
			recordErrs = append(recordErrs, cleanupErr)
		}
	} else if cleanupErr != nil {
		recordErrs = append(recordErrs, cleanupErr)
	}
	if artifactRecord, recordArtifactErr := recordFactoryRunRecordArtifactWithRedactor(store, failedRecord, redactor); recordArtifactErr != nil {
		recordErrs = append(recordErrs, recordArtifactErr)
	} else {
		failedRecord = artifactRecord
	}
	if len(recordErrs) > 0 {
		return factoryRunExecutionResult{Record: failedRecord}, redactFactoryRunError(errors.Join(append([]error{artifactErr}, recordErrs...)...), redactor)
	}
	return factoryRunExecutionResult{Record: failedRecord, Render: true}, redactFactoryRunError(artifactErr, redactor)
}

func autoFactoryAttemptPolicyFromFactoryPolicy(policy factory.FactoryPolicy) autoFactoryAttemptPolicy {
	return autoFactoryAttemptPolicy{
		MaxRunAttempts:       policy.MaxRunAttempts,
		MaxReviewFixAttempts: policy.MaxReviewFixAttempts,
		MaxCIFixAttempts:     policy.MaxCIFixAttempts,
	}
}

func factoryPolicyDecisionFromAttemptLimit(err error) (factory.PolicyDecisionMetadata, bool) {
	var limitErr *compound.PolicyLimitError
	if !errors.As(err, &limitErr) || limitErr == nil {
		return factory.PolicyDecisionMetadata{}, false
	}
	return factory.PolicyDecisionMetadata{
		PolicyField: limitErr.PolicyField,
		Decision:    factory.PolicyDecisionBlockedGate,
		Outcome:     factory.PolicyOutcomeBlocked,
		Reason:      limitErr.Reason(),
	}, true
}

func failFactoryRunCreation(store factory.Store, record factory.RunRecord, out io.Writer, jsonMode bool, failedAt time.Time, cause error, decision *factory.PolicyDecisionMetadata) error {
	return failFactoryRunCreationWithRedactor(store, record, out, jsonMode, failedAt, cause, decision, factory.RunSecretRedactor{})
}

func failFactoryRunCreationWithRedactor(store factory.Store, record factory.RunRecord, out io.Writer, jsonMode bool, failedAt time.Time, cause error, decision *factory.PolicyDecisionMetadata, redactor factory.RunSecretRedactor) error {
	var recordErrs []error
	if decision != nil {
		if err := recordFactoryPolicyDecision(store, record.RunID, failedAt, *decision); err != nil {
			recordErrs = append(recordErrs, fmt.Errorf("record factory policy rejection: %w", err))
		}
	}

	failedRecord, err := markFactoryRunFailedWithRedactor(store, record, failedAt, cause, redactor)
	if err != nil {
		recordErrs = append(recordErrs, err)
	} else if failedRecord.Failure != nil {
		if eventErr := recordFactoryRunFailureClassified(store, failedRecord.RunID, failedAt, *failedRecord.Failure); eventErr != nil {
			recordErrs = append(recordErrs, fmt.Errorf("record factory failure classification event: %w", eventErr))
		}
	}
	if renderErr := renderFactoryRunResult(out, store, record.RunID, jsonMode); renderErr != nil {
		recordErrs = append(recordErrs, renderErr)
	}
	if len(recordErrs) > 0 {
		return redactFactoryRunError(errors.Join(append([]error{cause}, recordErrs...)...), redactor)
	}
	return redactFactoryRunError(cause, redactor)
}

func factoryRunEngineTelemetry(dir string, deps factoryRunDeps) *factory.RunTelemetry {
	if deps.loadEngine == nil {
		return nil
	}

	engineName, err := deps.loadEngine(dir)
	if err != nil {
		return nil
	}
	engineName = strings.ToLower(strings.TrimSpace(engineName))
	if engineName == "" {
		return nil
	}

	model := ""
	if deps.loadEngineConfig != nil {
		if cfg := deps.loadEngineConfig(dir, engineName); cfg != nil {
			model = strings.TrimSpace(cfg.Model)
		}
	}

	return &factory.RunTelemetry{
		Engine: &factory.EngineTelemetry{
			Name:  engineName,
			Model: model,
		},
	}
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
	return markFactoryRunInProgressWithRedactor(store, record, now, factory.RunSecretRedactor{})
}

func markFactoryRunInProgressWithRedactor(store factory.Store, record factory.RunRecord, now time.Time, redactor factory.RunSecretRedactor) (factory.RunRecord, error) {
	record.Status = factory.RunStatusRunning
	record.CurrentStep = "run"
	record.UpdatedAt = now.UTC()
	safeRecord := redactFactoryRunRecordForStorage(record, redactor)
	if err := store.SaveRun(&safeRecord); err != nil {
		return factory.RunRecord{}, fmt.Errorf("mark factory run in progress: %w", err)
	}
	return record, nil
}

func recordFactoryRunArtifacts(ctx context.Context, store factory.Store, runID, dir string, req factoryRunRequest, snapshot factoryArtifactSnapshot, now time.Time, deps factoryRunDeps, collectSandboxArtifacts bool, redactor factory.RunSecretRedactor) (factory.RunRecord, error) {
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
	outcomes, outcomeCleanup, err := materializeFactoryOutcomeArtifacts(dir, record.CreatedAt)
	if outcomeCleanup != nil {
		defer outcomeCleanup()
	}
	if err != nil {
		return factory.RunRecord{}, err
	}
	snapshots = append(snapshots, outcomes...)

	if err := collectAndStoreFactoryRunArtifacts(store, dir, req, *record, snapshot, snapshots); err != nil {
		return factory.RunRecord{}, err
	}
	if collectSandboxArtifacts {
		if err := collectAndStoreFactorySandboxArtifacts(ctx, store, dir, req, *record, deps); err != nil {
			return factory.RunRecord{}, err
		}
	}
	record, err = store.LoadRun(runID)
	if err != nil {
		return factory.RunRecord{}, fmt.Errorf("reload factory run artifacts: %w", err)
	}
	record.UpdatedAt = now.UTC()
	safeRecord := redactFactoryRunRecordForStorage(*record, redactor)
	if err := store.SaveRun(&safeRecord); err != nil {
		return factory.RunRecord{}, fmt.Errorf("record factory artifacts: %w", err)
	}
	return safeRecord, nil
}

func recordFactoryRunVerification(ctx context.Context, store factory.Store, record factory.RunRecord, dir string, deps factoryRunDeps, policy factory.FactoryPolicy, resolvedSecrets []factory.ResolvedRunSecret, redactor factory.RunSecretRedactor) (factory.RunRecord, time.Time, error) {
	startedAt := deps.now()
	record.CurrentStep = "verify"
	record.UpdatedAt = startedAt.UTC()
	safeRecord := redactFactoryRunRecordForStorage(record, redactor)
	if err := store.SaveRun(&safeRecord); err != nil {
		return record, deps.now(), fmt.Errorf("mark factory run verifying: %w", err)
	}

	if factoryRunUsesSandboxVerification(record) {
		result, updatedRecord, err := runFactorySandboxRemoteVerification(ctx, store, dir, record, deps, resolvedSecrets, redactor)
		finishedAt := deps.now()
		if err != nil {
			return record, finishedAt, fmt.Errorf("run remote sandbox verification: %w", err)
		}
		return recordFactoryRunVerificationOutcome(store, dir, updatedRecord, startedAt, finishedAt, result, policy, redactor, false)
	}

	cfg, err := deps.loadVerify(dir)
	if err != nil {
		return record, deps.now(), fmt.Errorf("load verification config: %w", err)
	}
	if cfg == nil || len(cfg.Checks) == 0 {
		if policy.VerificationRequired {
			finishedAt := deps.now()
			decision := factory.PolicyDecisionMetadata{
				PolicyField: "factory.policy.verificationRequired",
				Decision:    factory.PolicyDecisionBlockedGate,
				Outcome:     factory.PolicyOutcomeBlocked,
				Reason:      "verification required but no checks configured",
			}
			if err := recordFactoryPolicyDecision(store, record.RunID, finishedAt, decision); err != nil {
				return record, finishedAt, fmt.Errorf("record factory verification policy decision: %w", err)
			}
			return record, finishedAt, fmt.Errorf("verification required but no checks configured")
		}
		return record, deps.now(), nil
	}
	if err := recordFactoryRunVerificationStarted(store, record.RunID, startedAt); err != nil {
		return record, deps.now(), fmt.Errorf("record factory verification start event: %w", err)
	}

	result, err := deps.runVerify(ctx, cfg)
	finishedAt := deps.now()
	if err != nil {
		return record, finishedAt, fmt.Errorf("run verification: %w", err)
	}
	if result == nil {
		return record, finishedAt, fmt.Errorf("run verification: no result")
	}

	return recordFactoryRunVerificationOutcome(store, dir, record, startedAt, finishedAt, result, policy, redactor, true)
}

func recordFactoryRunVerificationOutcome(store factory.Store, dir string, record factory.RunRecord, startedAt, finishedAt time.Time, result *verify.Result, policy factory.FactoryPolicy, redactor factory.RunSecretRedactor, startedRecorded bool) (factory.RunRecord, time.Time, error) {
	if result == nil {
		return record, finishedAt, fmt.Errorf("run verification: no result")
	}
	if factoryVerificationResultHasNoChecks(result) {
		if policy.VerificationRequired {
			decision := factory.PolicyDecisionMetadata{
				PolicyField: "factory.policy.verificationRequired",
				Decision:    factory.PolicyDecisionBlockedGate,
				Outcome:     factory.PolicyOutcomeBlocked,
				Reason:      "verification required but no checks configured",
			}
			if err := recordFactoryPolicyDecision(store, record.RunID, finishedAt, decision); err != nil {
				return record, finishedAt, fmt.Errorf("record factory verification policy decision: %w", err)
			}
			return record, finishedAt, fmt.Errorf("verification required but no checks configured")
		}
		return record, finishedAt, nil
	}
	if !startedRecorded {
		if err := recordFactoryRunVerificationStarted(store, record.RunID, startedAt); err != nil {
			return record, finishedAt, fmt.Errorf("record factory verification start event: %w", err)
		}
	}

	safeArtifacts := redactFactoryVerificationArtifacts(result.Artifacts, redactor)
	record.Verification = &factory.VerificationRecord{
		Summary:   result.Summary,
		Artifacts: safeArtifacts,
	}
	record.UpdatedAt = finishedAt.UTC()
	safeRecord := redactFactoryRunRecordForStorage(record, redactor)
	if err := store.SaveRun(&safeRecord); err != nil {
		return factory.RunRecord{}, finishedAt, fmt.Errorf("record factory verification: %w", err)
	}
	if err := collectAndStoreFactoryVerificationArtifacts(store, dir, record.RunID, result.Artifacts, redactor); err != nil {
		return factory.RunRecord{}, finishedAt, err
	}
	updatedRecord, err := store.LoadRun(record.RunID)
	if err != nil {
		return factory.RunRecord{}, finishedAt, fmt.Errorf("reload factory run verification artifacts: %w", err)
	}
	record = *updatedRecord
	if err := recordFactoryRunVerificationResultWithRedactor(store, record.RunID, finishedAt, *result, redactor); err != nil {
		return record, finishedAt, fmt.Errorf("record factory verification event: %w", err)
	}
	if result.Status == verify.StatusFail {
		if !policy.VerificationRequired {
			decision := factory.PolicyDecisionMetadata{
				PolicyField: "factory.policy.verificationRequired",
				Decision:    factory.PolicyDecisionAllowedExecution,
				Outcome:     factory.PolicyOutcomeAllowed,
				Reason:      "verification not required; advisory failure did not block",
			}
			if err := recordFactoryPolicyDecision(store, record.RunID, finishedAt, decision); err != nil {
				return record, finishedAt, fmt.Errorf("record factory verification policy decision: %w", err)
			}
			if err := recordFactoryRunVerificationAdvisoryFailed(store, record.RunID, finishedAt, newFactoryRunVerificationFailure(result)); err != nil {
				return record, finishedAt, fmt.Errorf("record factory advisory verification failure event: %w", err)
			}
			return record, finishedAt, nil
		}
		decision := factory.PolicyDecisionMetadata{
			PolicyField: "factory.policy.verificationRequired",
			Decision:    factory.PolicyDecisionBlockedGate,
			Outcome:     factory.PolicyOutcomeBlocked,
			Reason:      "verification failed",
		}
		if err := recordFactoryPolicyDecision(store, record.RunID, finishedAt, decision); err != nil {
			return record, finishedAt, fmt.Errorf("record factory verification policy decision: %w", err)
		}
		return record, finishedAt, newFactoryRunVerificationFailure(result)
	}
	if policy.VerificationRequired {
		decision := factory.PolicyDecisionMetadata{
			PolicyField: "factory.policy.verificationRequired",
			Decision:    factory.PolicyDecisionPassedGate,
			Outcome:     factory.PolicyOutcomePassed,
			Reason:      "verification passed",
		}
		if err := recordFactoryPolicyDecision(store, record.RunID, finishedAt, decision); err != nil {
			return record, finishedAt, fmt.Errorf("record factory verification policy decision: %w", err)
		}
	}
	if err := recordFactoryRunVerificationSucceeded(store, record.RunID, finishedAt); err != nil {
		return record, finishedAt, fmt.Errorf("record factory verification completion event: %w", err)
	}
	return record, finishedAt, nil
}

func factoryVerificationResultHasNoChecks(result *verify.Result) bool {
	if result == nil {
		return true
	}
	return result.Summary.Total == 0 && len(result.Checks) == 0
}

func factoryRunUsesSandboxVerification(record factory.RunRecord) bool {
	return strings.TrimSpace(record.ExecutorMode) == factory.ExecutorModeSandbox
}

func runFactorySandboxRemoteVerification(ctx context.Context, store factory.Store, dir string, record factory.RunRecord, deps factoryRunDeps, resolvedSecrets []factory.ResolvedRunSecret, redactor factory.RunSecretRedactor) (*verify.Result, factory.RunRecord, error) {
	sandboxName := factoryRunSandboxName(record)
	if sandboxName == "" {
		return nil, record, fmt.Errorf("sandbox verification requires sandbox metadata")
	}
	target, err := deps.loadSandbox(sandboxName)
	if err != nil {
		return nil, record, fmt.Errorf("load sandbox %q for verification: %w", sandboxName, err)
	}
	if target == nil {
		return nil, record, fmt.Errorf("load sandbox %q for verification: not found", sandboxName)
	}
	provider, err := deps.resolveProvider(dir, target.Provider)
	if err != nil {
		return nil, record, fmt.Errorf("resolve sandbox provider %q for verification: %w", target.Provider, err)
	}
	args, err := factorySandboxRemoteVerifyArgs(record)
	if err != nil {
		return nil, record, err
	}
	var out bytes.Buffer
	execErr := deps.runProviderExecWithEnv(ctx, provider, sandbox.ConnectInfoFromState(target), args, factorySandboxResolvedSecretEnv(resolvedSecrets), &out)
	result, parseErr := parseFactorySandboxVerifyResult(out.Bytes())
	if parseErr != nil {
		if execErr != nil {
			return nil, record, fmt.Errorf("remote verify command failed (%w) and output was not valid verify JSON: %v", execErr, parseErr)
		}
		return nil, record, parseErr
	}
	if err := collectAndStoreFactorySandboxVerificationArtifacts(ctx, store, record, result.Artifacts, target, provider, deps, redactor); err != nil {
		return nil, record, err
	}
	updatedRecord, err := store.LoadRun(record.RunID)
	if err != nil {
		return nil, record, fmt.Errorf("reload factory run verification artifacts: %w", err)
	}
	return result, *updatedRecord, nil
}

func factoryRunSandboxName(record factory.RunRecord) string {
	if name := strings.TrimSpace(record.SandboxName); name != "" {
		return name
	}
	if record.Sandbox != nil {
		return strings.TrimSpace(record.Sandbox.Name)
	}
	return ""
}

func factorySandboxRemoteVerifyArgs(record factory.RunRecord) ([]string, error) {
	workspaceDir := factorySandboxRemoteWorkspaceDir(record)
	if workspaceDir == "" {
		return nil, errFactorySandboxWorkspaceRequired
	}
	verifyCommand := shellCommand([]string{"hal", "verify", "--json"}) + " 2>/tmp/hal-factory-verify-stderr"
	return []string{"sh", "-lc", "cd " + shellQuote(workspaceDir) + " && exec " + verifyCommand}, nil
}

func parseFactorySandboxVerifyResult(data []byte) (*verify.Result, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("parse remote sandbox verify JSON: empty output")
	}
	var result verify.Result
	if err := json.Unmarshal(trimmed, &result); err != nil {
		return nil, fmt.Errorf("parse remote sandbox verify JSON: %w", err)
	}
	return &result, nil
}

func collectAndStoreFactorySandboxVerificationArtifacts(ctx context.Context, store factory.Store, record factory.RunRecord, artifacts []verify.ArtifactReference, target *sandbox.SandboxState, provider sandbox.Provider, deps factoryRunDeps, redactor factory.RunSecretRedactor) error {
	if len(artifacts) == 0 {
		return nil
	}
	workspaceDir := factorySandboxRemoteWorkspaceDir(record)
	if workspaceDir == "" {
		return errFactorySandboxWorkspaceRequired
	}
	requests := make([]factory.SandboxArtifactRequest, 0, len(artifacts))
	for _, artifact := range artifacts {
		path := strings.TrimSpace(artifact.Path)
		if path == "" {
			continue
		}
		remotePath := path
		if !filepath.IsAbs(remotePath) {
			remotePath = filepath.ToSlash(filepath.Join(workspaceDir, remotePath))
		}
		nameParts := []string{"verification"}
		if checkID := strings.TrimSpace(artifact.CheckID); checkID != "" {
			nameParts = append(nameParts, sanitizeFactoryArtifactPathComponent(checkID))
		}
		if kind := strings.TrimSpace(artifact.Kind); kind != "" {
			nameParts = append(nameParts, sanitizeFactoryArtifactPathComponent(kind))
		}
		requests = append(requests, factory.SandboxArtifactRequest{
			ID:         factorySandboxVerificationArtifactID(artifact),
			Name:       strings.Join(nameParts, "-"),
			Type:       factoryArtifactTypeForPath(path),
			RemotePath: filepath.ToSlash(remotePath),
			Path:       filepath.ToSlash(filepath.Clean(path)),
			Optional:   true,
			Summary: map[string]any{
				"checkId":      artifact.CheckID,
				"kind":         artifact.Kind,
				"executorMode": factory.ExecutorModeSandbox,
				"sandboxName":  record.SandboxName,
			},
		})
	}
	if len(requests) == 0 {
		return nil
	}
	copier := factoryProviderExecSandboxArtifactCopier{
		provider:        provider,
		connectInfo:     sandbox.ConnectInfoFromState(target),
		runProviderExec: deps.runProviderExec,
	}
	if _, err := factory.CollectSandboxArtifactsWithRedactor(ctx, store, record.RunID, &copier, requests, redactor); err != nil {
		return fmt.Errorf("collect sandbox verification artifacts: %w", err)
	}
	return nil
}

func factorySandboxVerificationArtifactID(artifact verify.ArtifactReference) string {
	parts := []string{"verification"}
	for _, value := range []string{artifact.CheckID, artifact.Kind, artifact.Path} {
		if part := sanitizeFactoryArtifactPathComponent(value); part != "" {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, "-")
}

type factoryProviderExecSandboxArtifactCopier struct {
	provider        sandbox.Provider
	connectInfo     *sandbox.ConnectInfo
	runProviderExec func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error
}

func (c *factoryProviderExecSandboxArtifactCopier) CopyFile(ctx context.Context, remotePath, localPath string) error {
	remotePath = strings.TrimSpace(remotePath)
	if remotePath == "" {
		return factory.ErrSandboxArtifactNotFound
	}
	var out bytes.Buffer
	args := []string{"sh", "-lc", "if [ ! -f " + shellQuote(remotePath) + " ]; then printf %s " + shellQuote(factorySandboxArtifactMissingSentinel) + "; exit 0; fi; base64 < " + shellQuote(remotePath)}
	if err := c.runProviderExec(ctx, c.provider, c.connectInfo, args, &out); err != nil {
		return err
	}
	payload := strings.TrimSpace(out.String())
	if payload == factorySandboxArtifactMissingSentinel {
		return factory.ErrSandboxArtifactNotFound
	}
	data, err := decodeFactorySandboxBase64Payload(payload)
	if err != nil {
		return fmt.Errorf("decode sandbox artifact %q: %w", remotePath, err)
	}
	if err := os.MkdirAll(filepath.Dir(localPath), 0o700); err != nil {
		return fmt.Errorf("create sandbox artifact destination: %w", err)
	}
	if err := os.WriteFile(localPath, data, 0o600); err != nil {
		return fmt.Errorf("write sandbox artifact %q: %w", remotePath, err)
	}
	return nil
}

func (c *factoryProviderExecSandboxArtifactCopier) CopyDir(ctx context.Context, remotePath, localPath string) error {
	remotePath = strings.TrimSpace(remotePath)
	if remotePath == "" {
		return factory.ErrSandboxArtifactNotFound
	}
	var out bytes.Buffer
	args := []string{"sh", "-lc", "if [ ! -d " + shellQuote(remotePath) + " ]; then printf %s " + shellQuote(factorySandboxArtifactMissingSentinel) + "; exit 0; fi; tar -C " + shellQuote(remotePath) + " -cf - . | base64"}
	if err := c.runProviderExec(ctx, c.provider, c.connectInfo, args, &out); err != nil {
		return err
	}
	payload := strings.TrimSpace(out.String())
	if payload == factorySandboxArtifactMissingSentinel {
		return factory.ErrSandboxArtifactNotFound
	}
	data, err := decodeFactorySandboxBase64Payload(payload)
	if err != nil {
		return fmt.Errorf("decode sandbox artifact directory %q: %w", remotePath, err)
	}
	if err := os.MkdirAll(localPath, 0o700); err != nil {
		return fmt.Errorf("create sandbox artifact directory destination: %w", err)
	}
	reader := tar.NewReader(bytes.NewReader(data))
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read sandbox artifact directory %q: %w", remotePath, err)
		}
		name := filepath.Clean(strings.TrimSpace(header.Name))
		if name == "" || name == "." {
			continue
		}
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return fmt.Errorf("sandbox artifact directory contains unsafe path %q", header.Name)
		}
		destination := filepath.Join(localPath, name)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(destination, 0o700); err != nil {
				return fmt.Errorf("create sandbox artifact directory %q: %w", name, err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
				return fmt.Errorf("create sandbox artifact parent %q: %w", name, err)
			}
			file, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return fmt.Errorf("create sandbox artifact file %q: %w", name, err)
			}
			_, copyErr := io.Copy(file, reader)
			closeErr := file.Close()
			if copyErr != nil {
				return fmt.Errorf("write sandbox artifact file %q: %w", name, copyErr)
			}
			if closeErr != nil {
				return fmt.Errorf("close sandbox artifact file %q: %w", name, closeErr)
			}
		default:
			continue
		}
	}
	return nil
}

func decodeFactorySandboxBase64Payload(payload string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || r == ' ' {
			return -1
		}
		return r
	}, payload))
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

func materializeFactorySnapshotArtifacts(dir string, deps factoryRunDeps) ([]factory.ArtifactReference, func(), error) {
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

func materializeFactoryOutcomeArtifacts(dir string, startedAt time.Time) ([]factory.ArtifactReference, func(), error) {
	state := factoryOutcomePipelineState(dir, startedAt)
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

func factoryOutcomePipelineState(dir string, startedAt time.Time) *compound.PipelineState {
	liveState, ok := loadFactoryRunPipelineState(filepath.Join(dir, template.HalDir, template.AutoStateFile))
	if ok && factoryPipelineStateHasOutcomeData(liveState) {
		return liveState
	}

	archived := collectFactoryRunArchivedArtifacts(dir, startedAt)
	for i := range archived.pipelineStates {
		state := &archived.pipelineStates[i]
		if factoryPipelineStateHasOutcomeData(state) {
			return state
		}
	}

	if ok {
		return liveState
	}
	return nil
}

func redactFactoryVerificationArtifacts(artifacts []verify.ArtifactReference, redactor factory.RunSecretRedactor) []verify.ArtifactReference {
	if len(artifacts) == 0 {
		return nil
	}
	safe := make([]verify.ArtifactReference, len(artifacts))
	for i, artifact := range artifacts {
		safe[i] = verify.ArtifactReference{
			CheckID: redactor.RedactString(artifact.CheckID),
			Kind:    redactor.RedactString(artifact.Kind),
			Path:    redactor.RedactString(artifact.Path),
		}
	}
	return safe
}

func factoryPipelineStateHasOutcomeData(state *compound.PipelineState) bool {
	if state == nil || state.CI == nil {
		return false
	}
	return safeFactoryPRURL(state.CI.PRURL) != "" || strings.TrimSpace(state.CI.Status) != ""
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
		if factoryArtifactSecretKey(key) {
			return ""
		}
	}
	return parsed.String()
}

func markFactoryRunSucceeded(store factory.Store, record factory.RunRecord, now time.Time) (factory.RunRecord, error) {
	return markFactoryRunSucceededWithRedactor(store, record, now, factory.RunSecretRedactor{})
}

func markFactoryRunSucceededWithRedactor(store factory.Store, record factory.RunRecord, now time.Time, redactor factory.RunSecretRedactor) (factory.RunRecord, error) {
	finishedAt := now.UTC()
	record.Status = factory.RunStatusSucceeded
	record.CurrentStep = "done"
	record.UpdatedAt = finishedAt
	record.FinishedAt = &finishedAt
	record.Failure = nil
	safeRecord := redactFactoryRunRecordForStorage(record, redactor)
	if err := store.SaveRun(&safeRecord); err != nil {
		return factory.RunRecord{}, fmt.Errorf("mark factory run succeeded: %w", err)
	}
	return safeRecord, nil
}

func markFactoryRunFailed(store factory.Store, record factory.RunRecord, now time.Time, pipelineErr error) (factory.RunRecord, error) {
	return markFactoryRunFailedWithRedactor(store, record, now, pipelineErr, factory.RunSecretRedactor{})
}

func markFactoryRunFailedWithRedactor(store factory.Store, record factory.RunRecord, now time.Time, pipelineErr error, redactor factory.RunSecretRedactor) (factory.RunRecord, error) {
	finishedAt := now.UTC()
	existingFailure := record.Failure
	failure := newFactoryRunFailureSummary(record.RunID, record.CurrentStep, pipelineErr)
	failure = redactFactoryRunFailureSummary(failure, redactor)
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
		failure = redactFactoryRunFailureSummary(preserved, redactor)
	}
	record.Status = factory.RunStatusFailed
	record.CurrentStep = failure.Step
	record.UpdatedAt = finishedAt
	record.FinishedAt = &finishedAt
	record.Failure = &failure
	safeRecord := redactFactoryRunRecordForStorage(record, redactor)
	if err := store.SaveRun(&safeRecord); err != nil {
		return factory.RunRecord{}, fmt.Errorf("mark factory run failed: %w", err)
	}
	return safeRecord, nil
}

func factorySandboxPipelineRecordError(record factory.RunRecord, fallback error) error {
	if record.Failure != nil {
		if message := strings.TrimSpace(record.Failure.Message); message != "" {
			return errors.New(message)
		}
	}
	return fallback
}

func redactFactoryRunFailureSummary(failure factory.FailureSummary, redactor factory.RunSecretRedactor) factory.FailureSummary {
	failure.Step = redactor.RedactString(failure.Step)
	failure.Category = redactor.RedactString(failure.Category)
	failure.Message = redactor.RedactString(failure.Message)
	failure.SuggestedCommand = redactor.RedactString(failure.SuggestedCommand)
	return failure
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

	var policyErr *factoryPolicyRejectionError
	if errors.As(err, &policyErr) {
		return factory.FailureCategoryPRD
	}
	var policyLimitErr *compound.PolicyLimitError
	if errors.As(err, &policyLimitErr) && policyLimitErr != nil {
		if category, ok := factoryFailureCategoryForAutoStep(policyLimitErr.Step); ok {
			return category
		}
		return factory.FailureCategoryPRD
	}

	var exitErr *ExitCodeError
	if errors.As(err, &exitErr) && exitErr.Code == ExitCodeValidation {
		return factory.FailureCategoryPRD
	}

	step := autoFailedStep(err)
	if category, ok := factoryFailureCategoryForAutoStep(step); ok {
		return category
	}

	message := strings.ToLower(strings.TrimSpace(err.Error()))
	switch {
	case factoryFailureMessageContains(message, "queue", "queued", "claim factory queue", "factory queue"):
		return factory.FailureCategoryQueue
	case factoryFailureMessageContains(message, "sandbox", "remote sandbox", "provider exec"):
		return factory.FailureCategorySandbox
	case factoryFailureMessageContains(message, "review", "review loop"):
		return factory.FailureCategoryReview
	case factoryFailureMessageContains(message, "prd", "planning", "plan ", "convert", "conversion", "validation", "validate", "invalid"):
		return factory.FailureCategoryPRD
	case factoryFailureMessageContains(message, "verification", "verify"):
		return factory.FailureCategoryVerification
	case factoryFailureMessageContains(message, "engine", "codex", "claude"):
		return factory.FailureCategoryEngine
	case factoryFailureMessageContains(message, "github", "git ", " git", "merge-base", "commit", "branch"):
		return factory.FailureCategorySetup
	case factoryFailureMessageContains(message, " ci", "ci ", "ci:", "ci-", "ci_", "workflow", "status check", "check run"):
		return factory.FailureCategoryCI
	case factoryFailureMessageContains(message, "pipeline") || step != "":
		return factory.FailureCategoryRun
	default:
		return factory.FailureCategoryUnknown
	}
}

func factoryFailureCategoryForAutoStep(step string) (string, bool) {
	switch step {
	case compound.StepSpec, compound.StepConvert, compound.StepValidate:
		return factory.FailureCategoryPRD, true
	case compound.StepRun:
		return factory.FailureCategoryRun, true
	case compound.StepReview:
		return factory.FailureCategoryReview, true
	case compound.StepCI:
		return factory.FailureCategoryCI, true
	case compound.StepBranch:
		return factory.FailureCategorySetup, true
	default:
		return "", false
	}
}

func factoryRunFailureStep(currentStep string, err error) string {
	var policyErr *factoryPolicyRejectionError
	if errors.As(err, &policyErr) {
		return "policy"
	}
	var policyLimitErr *compound.PolicyLimitError
	if errors.As(err, &policyLimitErr) {
		return "policy"
	}
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
	switch factory.NormalizeFailureCategory(category) {
	case factory.FailureCategorySetup,
		factory.FailureCategoryEngine,
		factory.FailureCategoryPRD,
		factory.FailureCategoryRun,
		factory.FailureCategoryReview,
		factory.FailureCategoryVerification,
		factory.FailureCategoryCI,
		factory.FailureCategorySandbox,
		factory.FailureCategoryQueue:
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

type factoryRunRedactedError struct {
	message string
	cause   error
}

func (e factoryRunRedactedError) Error() string {
	return e.message
}

func (e factoryRunRedactedError) Unwrap() error {
	return e.cause
}

func redactFactoryRunError(err error, redactor factory.RunSecretRedactor) error {
	if err == nil {
		return nil
	}
	message := redactor.RedactString(err.Error())
	if message == err.Error() {
		return err
	}
	return factoryRunRedactedError{
		message: message,
		cause:   err,
	}
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
	return recordFactoryRunRecordArtifactWithRedactor(store, record, factory.RunSecretRedactor{})
}

func recordFactoryRunRecordArtifactWithRedactor(store factory.Store, record factory.RunRecord, redactor factory.RunSecretRedactor) (factory.RunRecord, error) {
	recordPath := factoryRunRecordArtifactPath(store, record.RunID)
	if recordPath == "" {
		return record, nil
	}
	artifact := factory.ArtifactReference{
		ID:   "factory-run-record",
		Name: "factory-run-record",
		Type: "json",
		Path: recordPath,
	}
	if _, err := store.SaveArtifactFileWithRedactor(record.RunID, artifact, recordPath, redactor); err != nil {
		return factory.RunRecord{}, fmt.Errorf("store factory run record artifact: %w", err)
	}
	updatedRecord, err := store.LoadRun(record.RunID)
	if err != nil {
		return factory.RunRecord{}, fmt.Errorf("reload factory run record artifact: %w", err)
	}
	return *updatedRecord, nil
}

func collectAndStoreFactoryRunArtifacts(store factory.Store, dir string, req factoryRunRequest, record factory.RunRecord, snapshot factoryArtifactSnapshot, snapshots []factory.ArtifactReference) error {
	artifacts := collectFactoryRunArtifacts(store, dir, req, record, snapshot, snapshots)
	redactor := factory.NewRunSecretRedactor(req.ResolvedSecrets)
	missingArtifacts := make([]factory.ArtifactReference, 0)
	for _, artifact := range artifacts {
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
			safeArtifact := redactor.RedactArtifactReference(artifact)
			if _, err := store.SaveArtifactFileWithRedactor(record.RunID, artifact, absoluteSourcePath, redactor); err != nil {
				return fmt.Errorf("store factory artifact %q from %s: %w", safeArtifact.Name, safeArtifact.Path, err)
			}
			continue
		}

		missing := artifact
		missing.ID = factoryArtifactID(missing)
		missing.Partial = true
		missing.Warnings = append(missing.Warnings, fmt.Sprintf("optional artifact not found: %s", artifact.Path))
		missing.Summary = mergeFactoryArtifactSummary(missing.Summary, map[string]any{
			"collectionStatus": "missing",
		})
		missingArtifacts = append(missingArtifacts, redactor.RedactArtifactReference(missing))
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

func collectAndStoreFactoryVerificationArtifacts(store factory.Store, dir, runID string, artifacts []verify.ArtifactReference, redactor factory.RunSecretRedactor) error {
	for _, artifact := range artifacts {
		path := strings.TrimSpace(artifact.Path)
		if path == "" {
			continue
		}
		sourcePath := path
		if !filepath.IsAbs(sourcePath) {
			sourcePath = filepath.Join(dir, sourcePath)
		}
		if !factoryArtifactFileExists(sourcePath) {
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
		if _, err := store.SaveArtifactFileWithRedactor(runID, ref, sourcePath, redactor); err != nil {
			return fmt.Errorf("store factory verification artifact %q from %s: %w", ref.Name, ref.Path, err)
		}
	}
	return nil
}

func collectAndStoreFactorySandboxArtifacts(ctx context.Context, store factory.Store, dir string, req factoryRunRequest, record factory.RunRecord, deps factoryRunDeps) error {
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
	if deps.sandboxCopier == nil {
		return nil
	}
	redactor := factory.NewRunSecretRedactor(req.ResolvedSecrets)
	if _, err := factory.CollectSandboxArtifactsWithRedactor(ctx, store, record.RunID, deps.sandboxCopier, requests, redactor); err != nil {
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
			"step":   factory.RunDurationStepEngineRun,
			"status": record.Status,
		},
	})
}

func recordFactoryRunProgress(store factory.Store, runID string, now time.Time, event factoryRunProgressEvent) error {
	return recordFactoryRunProgressWithRedactor(store, runID, now, event, factory.RunSecretRedactor{})
}

func recordFactoryRunProgressWithRedactor(store factory.Store, runID string, now time.Time, event factoryRunProgressEvent, redactor factory.RunSecretRedactor) error {
	safeEvent := redactFactoryTimelineEvent(factoryTimelineEvent{
		EventType: factory.EventTypeCommandOutputSummary,
		Message:   event.Message,
		Summary:   event.Summary,
		Metadata:  event.Metadata,
	}, redactor)
	if err := recordFactoryRunLogChunk(store, runID, factoryLogStreamFromMetadata(safeEvent.Metadata), factoryLogSourceFromMetadata(safeEvent.Metadata), safeEvent.Message, safeEvent.Summary, &now); err != nil {
		return err
	}
	return appendFactoryRunTimelineEventWithRedactor(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypeCommandOutputSummary,
		Message:   event.Message,
		Summary:   event.Summary,
		Metadata:  event.Metadata,
	}, redactor)
}

func recordFactoryRunVerificationResult(store factory.Store, runID string, now time.Time, result verify.Result) error {
	return recordFactoryRunVerificationResultWithRedactor(store, runID, now, result, factory.RunSecretRedactor{})
}

func recordFactoryRunVerificationResultWithRedactor(store factory.Store, runID string, now time.Time, result verify.Result, redactor factory.RunSecretRedactor) error {
	return appendFactoryRunTimelineEventWithRedactor(store, runID, now, factoryTimelineEvent{
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
	}, redactor)
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
			"step":   factory.RunDurationStepEngineRun,
			"status": factory.RunStatusSucceeded,
		},
	})
}

func recordFactoryRunPipelineFailed(store factory.Store, runID string, now time.Time, pipelineErr error) error {
	return recordFactoryRunPipelineFailedWithRedactor(store, runID, now, pipelineErr, factory.RunSecretRedactor{})
}

func recordFactoryRunPipelineFailedWithRedactor(store factory.Store, runID string, now time.Time, pipelineErr error, redactor factory.RunSecretRedactor) error {
	return appendFactoryRunTimelineEventWithRedactor(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypeStepEnded,
		Summary:   "Local compound pipeline failed",
		Metadata: map[string]any{
			"step":   factory.RunDurationStepEngineRun,
			"status": factory.RunStatusFailed,
			"error":  pipelineErr.Error(),
		},
	}, redactor)
}

func recordFactoryRunArtifactCollectionFailed(store factory.Store, runID string, now time.Time, artifactErr error) error {
	return recordFactoryRunArtifactCollectionFailedWithRedactor(store, runID, now, artifactErr, factory.RunSecretRedactor{})
}

func recordFactoryRunArtifactCollectionFailedWithRedactor(store factory.Store, runID string, now time.Time, artifactErr error, redactor factory.RunSecretRedactor) error {
	return appendFactoryRunTimelineEventWithRedactor(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypeStepEnded,
		Summary:   "Factory artifact collection failed",
		Metadata: map[string]any{
			"step":   factory.RunDurationStepArtifactCollect,
			"status": factory.RunStatusFailed,
			"error":  artifactErr.Error(),
		},
	}, redactor)
}

func recordFactoryRunVerificationStarted(store factory.Store, runID string, now time.Time) error {
	return appendFactoryRunTimelineEvent(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypeStepStarted,
		Summary:   "Verification started",
		Metadata: map[string]any{
			"step":   factory.RunDurationStepVerification,
			"status": factory.RunStatusRunning,
		},
	})
}

func recordFactoryRunVerificationSucceeded(store factory.Store, runID string, now time.Time) error {
	return appendFactoryRunTimelineEvent(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypeStepEnded,
		Summary:   "Verification completed",
		Metadata: map[string]any{
			"step":   factory.RunDurationStepVerification,
			"status": factory.RunStatusSucceeded,
		},
	})
}

func recordFactoryRunSetupFailed(store factory.Store, runID string, now time.Time, setupErr error) error {
	return recordFactoryRunSetupFailedWithRedactor(store, runID, now, setupErr, factory.RunSecretRedactor{})
}

func recordFactoryRunSetupFailedWithRedactor(store factory.Store, runID string, now time.Time, setupErr error, redactor factory.RunSecretRedactor) error {
	return appendFactoryRunTimelineEventWithRedactor(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypeStepEnded,
		Summary:   "Factory run setup failed",
		Metadata: map[string]any{
			"step":   "setup",
			"status": factory.RunStatusFailed,
			"error":  setupErr.Error(),
		},
	}, redactor)
}

func recordFactoryRunVerificationFailed(store factory.Store, runID string, now time.Time, verificationErr error) error {
	return recordFactoryRunVerificationFailedWithRedactor(store, runID, now, verificationErr, factory.RunSecretRedactor{})
}

func recordFactoryRunVerificationFailedWithRedactor(store factory.Store, runID string, now time.Time, verificationErr error, redactor factory.RunSecretRedactor) error {
	return appendFactoryRunTimelineEventWithRedactor(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypeStepEnded,
		Summary:   "Verification failed",
		Metadata: map[string]any{
			"step":   factory.RunDurationStepVerification,
			"status": factory.RunStatusFailed,
			"error":  verificationErr.Error(),
		},
	}, redactor)
}

func recordFactoryRunVerificationAdvisoryFailed(store factory.Store, runID string, now time.Time, verificationErr error) error {
	return appendFactoryRunTimelineEvent(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypeStepEnded,
		Summary:   "Verification failed (advisory)",
		Metadata: map[string]any{
			"step":     factory.RunDurationStepVerification,
			"status":   factory.RunStatusFailed,
			"advisory": true,
			"blocking": false,
			"error":    verificationErr.Error(),
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

func recordFactoryPolicyDecision(store factory.Store, runID string, now time.Time, decision factory.PolicyDecisionMetadata) error {
	return appendFactoryRunTimelineEvent(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypePolicyDecision,
		Summary:   factoryPolicyDecisionSummary(decision),
		Metadata:  decision.EventMetadata(),
	})
}

func factoryPolicyDecisionSummary(decision factory.PolicyDecisionMetadata) string {
	decisionName := strings.TrimSpace(decision.Decision)
	outcome := strings.TrimSpace(decision.Outcome)

	switch {
	case decisionName != "" && outcome != "":
		return fmt.Sprintf("Policy decision %s: %s", decisionName, outcome)
	case decisionName != "":
		return "Policy decision " + decisionName
	case outcome != "":
		return "Policy decision: " + outcome
	default:
		return "Policy decision recorded"
	}
}

func redactFactoryTimelineEvent(event factoryTimelineEvent, redactor factory.RunSecretRedactor) factoryTimelineEvent {
	event.Message = redactor.RedactString(event.Message)
	event.Summary = redactor.RedactString(event.Summary)
	event.Metadata = redactFactoryTimelineMetadata(event.Metadata, redactor)
	return event
}

func redactFactoryTimelineMetadata(metadata map[string]any, redactor factory.RunSecretRedactor) map[string]any {
	if len(metadata) == 0 {
		return nil
	}
	safe := make(map[string]any, len(metadata))
	for key, value := range metadata {
		safe[redactor.RedactString(key)] = redactFactoryTimelineValue(value, redactor)
	}
	return safe
}

func redactFactoryTimelineValue(value any, redactor factory.RunSecretRedactor) any {
	if value == nil {
		return value
	}
	redacted, ok := redactFactoryTimelineReflectValue(reflect.ValueOf(value), redactor)
	if !ok {
		return value
	}
	return redacted.Interface()
}

func redactFactoryTimelineReflectValue(value reflect.Value, redactor factory.RunSecretRedactor) (reflect.Value, bool) {
	if !value.IsValid() {
		return value, false
	}
	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return value, false
		}
		return redactFactoryTimelineReflectValue(value.Elem(), redactor)
	case reflect.Pointer:
		if value.IsNil() {
			return value, false
		}
		redacted, ok := redactFactoryTimelineReflectValue(value.Elem(), redactor)
		if !ok {
			return value, false
		}
		out := reflect.New(value.Type().Elem())
		out.Elem().Set(redacted)
		return out, true
	case reflect.String:
		redacted := redactor.RedactString(value.String())
		if redacted == value.String() {
			return value, false
		}
		return reflect.ValueOf(redacted).Convert(value.Type()), true
	case reflect.Slice:
		if value.IsNil() {
			return value, false
		}
		out := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
		changed := false
		for i := 0; i < value.Len(); i++ {
			item := value.Index(i)
			redacted, ok := redactFactoryTimelineReflectValue(item, redactor)
			if ok {
				out.Index(i).Set(redacted)
				changed = true
				continue
			}
			out.Index(i).Set(item)
		}
		return out, changed
	case reflect.Array:
		out := reflect.New(value.Type()).Elem()
		changed := false
		for i := 0; i < value.Len(); i++ {
			item := value.Index(i)
			redacted, ok := redactFactoryTimelineReflectValue(item, redactor)
			if ok {
				out.Index(i).Set(redacted)
				changed = true
				continue
			}
			out.Index(i).Set(item)
		}
		return out, changed
	case reflect.Map:
		if value.IsNil() {
			return value, false
		}
		out := reflect.MakeMapWithSize(value.Type(), value.Len())
		changed := false
		iter := value.MapRange()
		for iter.Next() {
			key := iter.Key()
			redactedKey, keyChanged := redactFactoryTimelineMapKey(key, redactor)
			if keyChanged {
				changed = true
			}
			item := iter.Value()
			redactedItem, itemChanged := redactFactoryTimelineReflectValue(item, redactor)
			if itemChanged {
				out.SetMapIndex(redactedKey, redactedItem)
				changed = true
				continue
			}
			out.SetMapIndex(redactedKey, item)
		}
		return out, changed
	default:
		return value, false
	}
}

func redactFactoryTimelineMapKey(key reflect.Value, redactor factory.RunSecretRedactor) (reflect.Value, bool) {
	redacted, ok := redactFactoryTimelineReflectValue(key, redactor)
	if !ok {
		return key, false
	}
	keyType := key.Type()
	if redacted.Type().AssignableTo(keyType) {
		return redacted, true
	}
	if redacted.Type().ConvertibleTo(keyType) {
		return redacted.Convert(keyType), true
	}
	return key, false
}

func appendFactoryRunTimelineEvent(store factory.Store, runID string, timestamp time.Time, event factoryTimelineEvent) error {
	return appendFactoryRunTimelineEventWithRedactor(store, runID, timestamp, event, factory.RunSecretRedactor{})
}

func appendFactoryRunTimelineEventWithRedactor(store factory.Store, runID string, timestamp time.Time, event factoryTimelineEvent, redactor factory.RunSecretRedactor) error {
	events, err := store.LoadEvents(runID)
	if err != nil {
		return fmt.Errorf("load factory timeline %q: %w", runID, err)
	}
	event = redactFactoryTimelineEvent(event, redactor)

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

func recordFactoryRunLogChunk(store factory.Store, runID, stream, source, text, summary string, createdAt *time.Time) error {
	runID = strings.TrimSpace(runID)
	if runID == "" {
		return nil
	}
	if strings.TrimSpace(store.Root()) == "" {
		return nil
	}
	text = sanitizeFactoryLogText(text)
	summary = sanitizeFactoryLogText(summary)
	if strings.TrimSpace(text) == "" && strings.TrimSpace(summary) == "" {
		return nil
	}
	timestamp := time.Now().UTC()
	if createdAt != nil && !createdAt.IsZero() {
		timestamp = createdAt.UTC()
	}
	chunk := factory.LogChunk{
		RunID:     runID,
		Stream:    normalizeFactoryLogStream(stream),
		Source:    normalizeFactoryLogSource(source),
		Text:      strings.TrimSpace(text),
		Summary:   strings.TrimSpace(summary),
		CreatedAt: timestamp,
	}
	if err := store.AppendLogChunk(&chunk); err != nil {
		return fmt.Errorf("append factory log chunk %q: %w", runID, err)
	}
	return nil
}

func factoryLogStreamFromMetadata(metadata map[string]any) string {
	if metadata != nil {
		if stream, ok := metadata["stream"].(string); ok {
			return stream
		}
	}
	return factory.LogStreamSummary
}

func factoryLogSourceFromMetadata(metadata map[string]any) string {
	if metadata != nil {
		if source, ok := metadata["source"].(string); ok {
			return source
		}
	}
	return factory.LogSourceLocalFactory
}

func normalizeFactoryLogStream(stream string) string {
	switch strings.TrimSpace(stream) {
	case factory.LogStreamStdout:
		return factory.LogStreamStdout
	case factory.LogStreamStderr:
		return factory.LogStreamStderr
	default:
		return factory.LogStreamSummary
	}
}

func normalizeFactoryLogSource(source string) string {
	switch strings.TrimSpace(source) {
	case factory.LogSourceRemoteSandbox:
		return factory.LogSourceRemoteSandbox
	case factory.LogSourceEngine:
		return factory.LogSourceEngine
	default:
		return factory.LogSourceLocalFactory
	}
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

	redactor := factory.NewRunSecretRedactor(req.Request.ResolvedSecrets)
	autoReq := factoryRunAutoRequestFromFactoryRequest(req.Request)
	autoReq.Engine = strings.TrimSpace(req.Engine)
	autoReq.AttemptPolicy = req.AttemptPolicy
	autoReq.SkipCI = req.SkipCI
	now := req.Now
	if now == nil {
		now = time.Now
	}
	startedAt := now()
	if err := recordFactoryRunLogChunk(req.Store, req.RunID, factory.LogStreamSummary, factory.LogSourceLocalFactory, "", "Starting local hal auto pipeline", &startedAt); err != nil {
		return err
	}
	err := deps.runAuto(ctx, autoReq)
	if err != nil {
		failedAt := now()
		_ = recordFactoryRunLogChunk(req.Store, req.RunID, factory.LogStreamStderr, factory.LogSourceLocalFactory, redactor.RedactString(err.Error()), "Local hal auto pipeline failed", &failedAt)
		return err
	}
	completedAt := now()
	if err := recordFactoryRunLogChunk(req.Store, req.RunID, factory.LogStreamSummary, factory.LogSourceLocalFactory, "", "Local hal auto pipeline completed", &completedAt); err != nil {
		return err
	}
	return nil
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
	ctx = contextWithAutoFactoryAttemptPolicy(ctx, req.AttemptPolicy)

	cmd, err := factoryRunAutoCommand(ctx, req)
	if err != nil {
		return err
	}
	return runAuto(cmd, req.Args)
}

func factoryRunAutoCommand(ctx context.Context, req factoryRunAutoRequest) (*cobra.Command, error) {
	cmd := &cobra.Command{Use: "auto"}
	cmd.SetContext(ctx)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.Flags().Bool("dry-run", false, "")
	cmd.Flags().Bool("resume", false, "")
	cmd.Flags().Bool("no-ci", req.SkipCI, "")
	cmd.Flags().Bool("skip-pr", false, "")
	cmd.Flags().Bool("no-review", false, "")
	cmd.Flags().String("mode", "", "")
	cmd.Flags().Int("review-streak", 0, "")
	cmd.Flags().Int("review-max", 0, "")
	cmd.Flags().String("report", strings.TrimSpace(req.ReportPath), "")
	engineName := factoryRunAutoEngine(req.Engine)
	cmd.Flags().String("engine", engineName, "")
	if strings.TrimSpace(req.Engine) != "" {
		if err := cmd.Flags().Set("engine", engineName); err != nil {
			return nil, err
		}
	}
	cmd.Flags().String("base", strings.TrimSpace(req.BaseBranch), "")
	cmd.Flags().Bool("json", false, "")

	return cmd, nil
}

func factoryRunAutoEngine(engineName string) string {
	engineName = normalizeFactoryRunEngineName(engineName)
	if engineName == "" {
		return factory.PolicyEngineCodex
	}
	return engineName
}

func factoryRunRequestFromCommand(cmd *cobra.Command, args []string) (factoryRunRequest, error) {
	reportPath := factoryRunReportFlag
	baseBranch := factoryRunBaseFlag
	secretEnv := append([]string(nil), factoryRunSecretEnvFlags...)
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
		if cmd.Flags().Lookup("secret-env") != nil {
			value, err := cmd.Flags().GetStringArray("secret-env")
			if err != nil {
				return factoryRunRequest{}, err
			}
			secretEnv = value
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
	req.Secrets, err = parseFactoryRunSecretEnvFlags(secretEnv)
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

func parseFactoryRunSecretEnvFlags(values []string) ([]factory.RunSecretInput, error) {
	if len(values) == 0 {
		return nil, nil
	}
	secrets := make([]factory.RunSecretInput, 0, len(values))
	for _, value := range values {
		name := strings.TrimSpace(value)
		if name == "" {
			return nil, fmt.Errorf("--secret-env requires a non-empty environment variable name")
		}
		if !isFactoryRunSecretEnvName(name) {
			return nil, fmt.Errorf("invalid --secret-env value: expected an environment variable name like GITHUB_TOKEN")
		}
		secrets = append(secrets, factory.RunSecretInput{
			Name:     name,
			Source:   factory.RunSecretSourceEnv,
			Required: true,
		})
	}
	return secrets, nil
}

func isFactoryRunSecretEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		ch := name[i]
		valid := ch == '_' || ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z'
		if i > 0 {
			valid = valid || ch >= '0' && ch <= '9'
		}
		if !valid {
			return false
		}
	}
	return true
}

func factoryRunSecretMetadataFromInputs(inputs []factory.RunSecretInput) []factory.RunSecretMetadata {
	if len(inputs) == 0 {
		return nil
	}
	metadata := make([]factory.RunSecretMetadata, 0, len(inputs))
	for _, input := range inputs {
		name := strings.TrimSpace(input.Name)
		source := strings.TrimSpace(input.Source)
		if name == "" && source == "" {
			continue
		}
		metadata = append(metadata, factory.RunSecretMetadata{
			Name:     name,
			Source:   source,
			Required: input.Required,
			Present:  false,
		})
	}
	return metadata
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

	handoff := factory.NewHandoffSummary(store, *record)
	if jsonMode {
		return renderFactoryStatusJSON(out, *record, events, factoryStatusJSONHandoff(handoff))
	}

	renderFactoryStatusTable(out, *record, events, &handoff)
	return nil
}

func factoryStatusJSONHandoff(handoff factory.HandoffSummary) *factory.HandoffSummary {
	if !handoff.HasActionableData() {
		return nil
	}
	return &handoff
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

func runFactoryLogs(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	jsonMode := factoryLogsJSONFlag

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

	return runFactoryLogsWithDeps(out, args[0], jsonMode, defaultFactoryLogsDeps)
}

func runFactoryLogsWithDeps(out io.Writer, runID string, jsonMode bool, deps factoryLogsDeps) error {
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
	if _, err := store.LoadRun(runID); errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("factory run %q not found", runID)
	} else if err != nil {
		return fmt.Errorf("load factory run %q: %w", runID, err)
	}
	chunks, err := store.LoadLogChunks(runID)
	if err != nil {
		return fmt.Errorf("load factory logs %q: %w", runID, err)
	}
	chunks = sanitizeFactoryLogChunks(chunks)

	if jsonMode {
		return renderFactoryLogsJSON(out, runID, chunks)
	}
	renderFactoryLogsTable(out, runID, chunks)
	return nil
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

func renderFactoryStatusJSON(out io.Writer, record factory.RunRecord, events []factory.EventRecord, handoff *factory.HandoffSummary) error {
	resp := FactoryStatusResponse{
		ContractVersion: FactoryStatusContractVersion,
		Run:             newFactoryStatusRun(record, events, handoff),
		Timeline:        normalizeFactoryTimelineEventsForContractV1(events),
	}
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal factory status: %w", err)
	}
	fmt.Fprintln(out, string(data))
	return nil
}

func renderFactoryLogsJSON(out io.Writer, runID string, chunks []factory.LogChunk) error {
	if chunks == nil {
		chunks = []factory.LogChunk{}
	}
	resp := FactoryLogsResponse{
		ContractVersion: FactoryLogsContractVersion,
		RunID:           runID,
		Chunks:          chunks,
	}
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal factory logs: %w", err)
	}
	fmt.Fprintln(out, string(data))
	return nil
}

func newFactoryStatusRun(record factory.RunRecord, events []factory.EventRecord, handoff *factory.HandoffSummary) FactoryStatusRun {
	return FactoryStatusRun{
		RunID:           record.RunID,
		Status:          record.Status,
		ExecutorMode:    record.ExecutorMode,
		Engine:          record.Engine,
		Source:          record.Source,
		RepoPath:        record.RepoPath,
		RepoRemote:      record.RepoRemote,
		BranchName:      record.BranchName,
		BaseBranch:      record.BaseBranch,
		Policy:          factoryPolicySnapshotPointer(record.Policy),
		PolicyDecisions: factoryPolicyDecisionsFromEvents(events),
		SandboxName:     record.SandboxName,
		Sandbox:         record.Sandbox,
		CurrentStep:     record.CurrentStep,
		CreatedAt:       record.CreatedAt,
		UpdatedAt:       record.UpdatedAt,
		FinishedAt:      record.FinishedAt,
		Secrets:         record.Secrets,
		Artifacts:       newFactoryArtifactSummaries(record.Artifacts),
		Verification:    record.Verification,
		Telemetry:       factory.DeriveRunTelemetry(record, events),
		Failure:         normalizedFactoryFailureSummary(record.Failure),
		Handoff:         handoff,
	}
}

func factoryPolicySnapshotPointer(policy *factory.FactoryPolicy) *factory.FactoryPolicy {
	if policy == nil {
		return nil
	}
	snapshot := *policy
	if policy.AllowedEngines != nil {
		snapshot.AllowedEngines = append([]string(nil), policy.AllowedEngines...)
	}
	return &snapshot
}

func factoryPolicyDecisionsFromEvents(events []factory.EventRecord) []factory.PolicyDecisionMetadata {
	decisions := make([]factory.PolicyDecisionMetadata, 0)
	for _, event := range events {
		if event.EventType != factory.EventTypePolicyDecision {
			continue
		}
		decision := factoryPolicyDecisionFromMetadata(event.Metadata)
		if decision.PolicyField == "" && decision.Decision == "" && decision.Outcome == "" && decision.Reason == "" {
			continue
		}
		decisions = append(decisions, decision)
	}
	if len(decisions) == 0 {
		return nil
	}
	return decisions
}

func factoryPolicyDecisionFromMetadata(metadata map[string]any) factory.PolicyDecisionMetadata {
	return factory.PolicyDecisionMetadata{
		PolicyField: stringFromFactoryMetadata(metadata, "policyField"),
		Decision:    stringFromFactoryMetadata(metadata, "decision"),
		Outcome:     stringFromFactoryMetadata(metadata, "outcome"),
		Reason:      stringFromFactoryMetadata(metadata, "reason"),
	}
}

func stringFromFactoryMetadata(metadata map[string]any, key string) string {
	if len(metadata) == 0 {
		return ""
	}
	if value, ok := metadata[key].(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
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
	summaries := make([]FactoryArtifactSummary, 0, len(artifacts))
	for _, artifact := range artifacts {
		entry := FactoryArtifactSummary{
			ID:         strings.TrimSpace(artifact.ID),
			Name:       strings.TrimSpace(artifact.Name),
			Type:       strings.TrimSpace(artifact.Type),
			Path:       sanitizeFactoryArtifactPath(artifact.Path),
			StoredPath: strings.TrimSpace(artifact.StoredPath),
			SizeBytes:  artifact.SizeBytes,
			CreatedAt:  artifact.CreatedAt,
			Summary:    sanitizeFactoryArtifactSummary(artifact.Summary),
			Warnings:   sanitizeFactoryArtifactWarnings(artifact.Warnings),
			Partial:    artifact.Partial,
		}
		if entry.Path == "" && entry.StoredPath == "" && artifact.URL != "" {
			entry.Path = "[redacted]"
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
	if factoryArtifactPathLooksLikeURL(path) {
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

func factoryArtifactPathLooksLikeURL(path string) bool {
	parsed, err := url.Parse(path)
	if err != nil {
		return true
	}
	return parsed.Scheme != "" || parsed.Host != ""
}

func factoryArtifactPathIsParentRelative(path string) bool {
	path = filepath.ToSlash(path)
	if path == ".." || strings.HasPrefix(path, "../") {
		return true
	}
	windowsPath := strings.ReplaceAll(path, `\`, "/")
	return windowsPath == ".." || strings.HasPrefix(windowsPath, "../")
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
		Telemetry:     factory.DeriveRunTelemetry(record, nil),
		Failure:       normalizedFactoryFailureSummary(record.Failure),
	}
}

func normalizedFactoryFailureSummary(failure *factory.FailureSummary) *factory.FailureSummary {
	if failure == nil {
		return nil
	}
	normalizedFailure := *failure
	normalizedFailure.Category = factory.NormalizeFailureCategoryForContractV1(normalizedFailure.Category)
	return &normalizedFailure
}

func normalizeFactoryTimelineEventsForContractV1(events []factory.EventRecord) []factory.EventRecord {
	if len(events) == 0 {
		return events
	}
	normalized := make([]factory.EventRecord, len(events))
	copy(normalized, events)
	for i, event := range normalized {
		if event.EventType != factory.EventTypeFailureClassification || event.Metadata == nil {
			continue
		}
		category, ok := event.Metadata["category"].(string)
		if !ok {
			continue
		}
		metadata := make(map[string]any, len(event.Metadata))
		for key, value := range event.Metadata {
			metadata[key] = value
		}
		metadata["category"] = factory.NormalizeFailureCategoryForContractV1(category)
		normalized[i].Metadata = metadata
	}
	return normalized
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

func renderFactoryStatusTable(out io.Writer, record factory.RunRecord, events []factory.EventRecord, handoff *factory.HandoffSummary) {
	telemetry := factory.DeriveRunTelemetry(record, events)
	fmt.Fprintf(out, "Run ID: %s\n", record.RunID)
	fmt.Fprintf(out, "Status: %s\n", record.Status)
	fmt.Fprintf(out, "Branch: %s\n", record.BranchName)
	fmt.Fprintf(out, "Step: %s\n", record.CurrentStep)
	fmt.Fprintf(out, "Updated: %s\n", formatFactoryListTime(record.UpdatedAt))
	renderFactoryStatusTelemetry(out, record, telemetry)
	renderFactoryHandoffDetails(out, handoff)
	fmt.Fprintf(out, "Timeline events: %d\n", len(events))
	if len(events) == 0 {
		return
	}

	fmt.Fprintln(out, "Timeline:")
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SEQUENCE\tSTEP\tSTATUS\tDURATION\tSUMMARY")
	durations := factoryStepDurationMap(telemetry)
	for _, event := range events {
		step := factoryTimelineStep(event)
		status := factoryTimelineStatus(event)
		duration := ""
		if event.EventType == factory.EventTypeStepEnded && step != "" {
			duration = durations[step]
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n",
			event.Sequence,
			factoryTimelineLabel(event, step),
			status,
			duration,
			event.Summary,
		)
	}
	_ = w.Flush()
}

func renderFactoryStatusTelemetry(out io.Writer, record factory.RunRecord, telemetry *factory.RunTelemetry) {
	if record.Failure != nil {
		category := factory.NormalizeFailureCategoryForContractV1(record.Failure.Category)
		if category != "" {
			fmt.Fprintf(out, "Failure category: %s\n", category)
		}
		if message := strings.TrimSpace(record.Failure.Message); message != "" {
			fmt.Fprintf(out, "Failure: %s\n", message)
		}
	}
	if telemetry == nil {
		return
	}
	if telemetry.TotalDurationMs != nil {
		fmt.Fprintf(out, "Duration: %s\n", formatFactoryDurationMs(*telemetry.TotalDurationMs))
	}
	if telemetry.Engine != nil {
		parts := compactFactoryParts(telemetry.Engine.Name, telemetry.Engine.Model)
		if len(parts) > 0 {
			fmt.Fprintf(out, "Engine: %s\n", strings.Join(parts, " "))
		}
	}
	if telemetry.Sandbox != nil {
		parts := compactFactoryParts(telemetry.Sandbox.Provider, telemetry.Sandbox.Size)
		if len(parts) > 0 {
			fmt.Fprintf(out, "Sandbox: %s\n", strings.Join(parts, " "))
		}
	}
	if telemetry.EstimatedSandboxCost != nil && telemetry.EstimatedSandboxCost.Estimated {
		fmt.Fprintf(out, "Est. sandbox cost: $%.4f\n", telemetry.EstimatedSandboxCost.AmountUSD)
	}
	if outcome := strings.TrimSpace(telemetry.CIOutcome); outcome != "" {
		fmt.Fprintf(out, "CI: %s\n", outcome)
	}
	if outcome := strings.TrimSpace(telemetry.VerificationOutcome); outcome != "" {
		fmt.Fprintf(out, "Verification: %s\n", outcome)
	}
	if telemetry.ArtifactCount != nil {
		fmt.Fprintf(out, "Artifacts: %d\n", *telemetry.ArtifactCount)
	}
}

func renderFactoryArtifactsTable(out io.Writer, record factory.RunRecord) {
	fmt.Fprintf(out, "Run ID: %s\n", record.RunID)
	if len(record.Artifacts) == 0 {
		fmt.Fprintf(out, "No artifacts collected for factory run %s.\n", record.RunID)
		return
	}

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tTYPE\tPATH\tSTORED PATH\tSUMMARY\tWARNINGS")
	for _, artifact := range record.Artifacts {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			artifact.Name,
			artifact.Type,
			factoryArtifactDisplayPath(artifact),
			artifact.StoredPath,
			formatFactoryArtifactSummary(artifact.Summary),
			formatFactoryArtifactWarnings(artifact),
		)
	}
	_ = w.Flush()
}

func renderFactoryLogsTable(out io.Writer, runID string, chunks []factory.LogChunk) {
	fmt.Fprintf(out, "Run ID: %s\n", runID)
	if len(chunks) == 0 {
		fmt.Fprintf(out, "No logs stored for factory run %s.\n", runID)
		return
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SEQUENCE\tSTREAM\tSOURCE\tCREATED\tTEXT")
	for _, chunk := range chunks {
		text := strings.TrimSpace(chunk.Text)
		if text == "" {
			text = strings.TrimSpace(chunk.Summary)
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n",
			chunk.Sequence,
			chunk.Stream,
			chunk.Source,
			formatFactoryListTime(chunk.CreatedAt),
			text,
		)
	}
	_ = w.Flush()
}

func factoryStepDurationMap(telemetry *factory.RunTelemetry) map[string]string {
	durations := map[string]string{}
	if telemetry == nil {
		return durations
	}
	for _, step := range telemetry.StepDurations {
		if strings.TrimSpace(step.Step) == "" {
			continue
		}
		durations[step.Step] = formatFactoryDurationMs(step.DurationMs)
	}
	return durations
}

func factoryTimelineStep(event factory.EventRecord) string {
	if event.Metadata == nil {
		return ""
	}
	step, _ := event.Metadata["step"].(string)
	return strings.TrimSpace(step)
}

func factoryTimelineStatus(event factory.EventRecord) string {
	if event.Metadata == nil {
		return ""
	}
	status, _ := event.Metadata["status"].(string)
	return strings.TrimSpace(status)
}

func factoryTimelineLabel(event factory.EventRecord, step string) string {
	if step != "" {
		return step
	}
	return event.EventType
}

func compactFactoryParts(values ...string) []string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			parts = append(parts, value)
		}
	}
	return parts
}

func formatFactoryDurationMs(ms int64) string {
	if ms < 0 {
		ms = 0
	}
	d := time.Duration(ms) * time.Millisecond
	if d >= time.Second {
		return d.Round(time.Second).String()
	}
	return d.String()
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
	warnings := append([]string(nil), artifact.Warnings...)
	if artifact.Partial && len(warnings) == 0 {
		warnings = append(warnings, "partial")
	}
	if len(warnings) == 0 {
		return "-"
	}
	return strings.Join(warnings, "; ")
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

func sanitizeFactoryLogChunks(chunks []factory.LogChunk) []factory.LogChunk {
	if len(chunks) == 0 {
		return nil
	}
	safe := make([]factory.LogChunk, 0, len(chunks))
	for _, chunk := range chunks {
		chunk.Stream = normalizeFactoryLogStream(chunk.Stream)
		chunk.Source = normalizeFactoryLogSource(chunk.Source)
		chunk.Text = sanitizeFactoryLogText(chunk.Text)
		chunk.Summary = sanitizeFactoryLogText(chunk.Summary)
		safe = append(safe, chunk)
	}
	return safe
}

func sanitizeFactoryLogText(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if factoryArtifactStringNeedsRedaction(value) || factoryLogContainsSecretAssignment(value) {
		return "[redacted]"
	}
	return value
}

func factoryLogContainsSecretAssignment(value string) bool {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == ';' || r == ','
	})
	for _, field := range fields {
		field = strings.Trim(field, `"'`)
		idx := strings.IndexAny(field, "=:")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(field[:idx])
		if factoryArtifactSecretKey(key) {
			return true
		}
	}
	return false
}

func sanitizeFactoryArtifactValue(key string, value any) any {
	if factoryArtifactSecretKey(key) {
		return "[redacted]"
	}
	switch v := value.(type) {
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
		return value
	}
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
				if factoryArtifactSecretKey(key) {
					return true
				}
			}
		}
	}
	if factoryArtifactStringContainsAbsolutePath(value) {
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

func sanitizeFactoryRunRecordCredentialedRemote(record factory.RunRecord) factory.RunRecord {
	record.RepoRemote = sanitizeCredentialedRemote(record.RepoRemote)
	return record
}

func redactFactoryRunRecordForStorage(record factory.RunRecord, redactor factory.RunSecretRedactor) factory.RunRecord {
	return sanitizeFactoryRunRecordCredentialedRemote(redactor.RedactRunRecord(record))
}

func sanitizeCredentialedRemote(remote string) string {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return remote
	}
	parsed, err := url.Parse(remote)
	if err != nil {
		if sanitized, ok := sanitizeCredentialedRemoteAuthority(remote); ok {
			return sanitizeCredentialedRemoteComponents(sanitized)
		}
		return sanitizeCredentialedRemoteComponents(remote)
	}

	changed := false
	if parsed.User != nil {
		userinfo := factory.RunSecretRedactionPlaceholder
		parsed.User = nil
		withoutUser := parsed.String()
		prefix := parsed.Scheme + "://"
		if parsed.Scheme == "" || !strings.HasPrefix(withoutUser, prefix) {
			return sanitizeCredentialedRemoteComponents(remote)
		}
		remote = prefix + userinfo + "@" + strings.TrimPrefix(withoutUser, prefix)
		parsed, err = url.Parse(remote)
		if err != nil {
			return sanitizeCredentialedRemoteComponents(remote)
		}
		changed = true
	}
	if sanitizedQuery, ok := sanitizeCredentialedRemoteParameters(parsed.RawQuery); ok {
		parsed.RawQuery = sanitizedQuery
		changed = true
	}
	if sanitizedFragment, ok := sanitizeCredentialedRemoteParameters(parsed.Fragment); ok {
		parsed.Fragment = sanitizedFragment
		parsed.RawFragment = sanitizedFragment
		changed = true
	}
	if !changed {
		return remote
	}
	return parsed.String()
}

func sanitizeCredentialedRemoteReferences(value string) string {
	if !strings.Contains(value, "://") {
		return value
	}
	var out strings.Builder
	for i := 0; i < len(value); {
		if strings.HasPrefix(value[i:], "https://") || strings.HasPrefix(value[i:], "http://") {
			end := i
			for end < len(value) && !factoryCredentialedRemoteReferenceSeparator(value[end]) {
				end++
			}
			out.WriteString(sanitizeCredentialedRemote(value[i:end]))
			i = end
			continue
		}
		out.WriteByte(value[i])
		i++
	}
	return out.String()
}

func factoryCredentialedRemoteReferenceSeparator(ch byte) bool {
	switch ch {
	case ' ', '\t', '\n', '\r':
		return true
	default:
		return false
	}
}

func sanitizeCredentialedRemoteAuthority(remote string) (string, bool) {
	schemeIndex := strings.Index(remote, "://")
	if schemeIndex < 0 {
		return remote, false
	}
	authorityStart := schemeIndex + len("://")
	authorityEnd := len(remote)
	for _, separator := range []string{"/", "?", "#"} {
		if index := strings.Index(remote[authorityStart:], separator); index >= 0 && authorityStart+index < authorityEnd {
			authorityEnd = authorityStart + index
		}
	}
	authority := remote[authorityStart:authorityEnd]
	atIndex := strings.LastIndex(authority, "@")
	if atIndex < 0 {
		return remote, false
	}
	return remote[:authorityStart] + factory.RunSecretRedactionPlaceholder + "@" + remote[authorityStart+atIndex+1:], true
}

func sanitizeCredentialedRemoteComponents(remote string) string {
	queryStart := strings.Index(remote, "?")
	fragmentStart := strings.Index(remote, "#")
	if queryStart < 0 && fragmentStart < 0 {
		return remote
	}

	queryEnd := len(remote)
	if fragmentStart >= 0 && (queryStart < 0 || fragmentStart > queryStart) {
		queryEnd = fragmentStart
	}
	if queryStart >= 0 {
		if sanitized, ok := sanitizeCredentialedRemoteParameters(remote[queryStart+1 : queryEnd]); ok {
			remote = remote[:queryStart+1] + sanitized + remote[queryEnd:]
			fragmentStart = strings.Index(remote, "#")
		}
	}
	if fragmentStart >= 0 {
		if sanitized, ok := sanitizeCredentialedRemoteParameters(remote[fragmentStart+1:]); ok {
			remote = remote[:fragmentStart+1] + sanitized
		}
	}
	return remote
}

func sanitizeCredentialedRemoteParameters(raw string) (string, bool) {
	if raw == "" {
		return raw, false
	}
	var out strings.Builder
	changed := false
	start := 0
	for i := 0; i <= len(raw); i++ {
		if i < len(raw) && raw[i] != '&' && raw[i] != ';' {
			continue
		}
		segment := raw[start:i]
		if sanitized, ok := sanitizeCredentialedRemoteParameter(segment); ok {
			out.WriteString(sanitized)
			changed = true
		} else {
			out.WriteString(segment)
		}
		if i < len(raw) {
			out.WriteByte(raw[i])
		}
		start = i + 1
	}
	if !changed {
		return raw, false
	}
	return out.String(), true
}

func sanitizeCredentialedRemoteParameter(segment string) (string, bool) {
	eq := strings.Index(segment, "=")
	if eq < 0 {
		return segment, false
	}
	key := segment[:eq]
	decodedKey, err := url.QueryUnescape(key)
	if err != nil {
		decodedKey = key
	}
	if !isCredentialedRemoteParameterKey(decodedKey) {
		return segment, false
	}
	return key + "=" + factory.RunSecretRedactionPlaceholder, true
}

func isCredentialedRemoteParameterKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	normalized = strings.NewReplacer("-", "_", ".", "_").Replace(normalized)
	switch normalized {
	case "token", "access_token", "api_key", "apikey", "credential", "credentials", "password", "passwd", "secret", "client_secret", "private_token", "auth_token":
		return true
	default:
		return strings.Contains(normalized, "token") ||
			strings.Contains(normalized, "secret") ||
			strings.Contains(normalized, "password") ||
			strings.Contains(normalized, "credential")
	}
}
