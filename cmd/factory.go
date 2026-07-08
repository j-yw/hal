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
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jywlabs/hal/internal/ci"
	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/doctor"
	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/prd"
	"github.com/jywlabs/hal/internal/projectconfig"
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
	FactoryRecoverContractVersion   = "factory-recover-v1"
	FactoryPublishContractVersion   = "factory-publish-v1"
)

var factoryListJSONFlag bool
var factoryStatusJSONFlag bool
var factoryArtifactsJSONFlag bool
var factoryLogsJSONFlag bool
var factoryRunReportFlag string
var factoryRunBaseFlag string
var factoryRunSecretEnvFlags []string
var factoryRunCIPolicyFlag string
var factoryRunNoCIFlag bool
var factoryRunPublishFlag string
var factoryRunPublishFromFlag string
var factoryRunJSONFlag bool
var factoryRunSandboxFlag bool
var factoryRunSandboxNameFlag string
var factoryRunSandboxHostFlag string
var factoryRunSandboxRuntimeFlag string
var factoryOpenExecFlag bool
var factoryOpenJSONFlag bool
var factoryRecoverJSONFlag bool
var factoryPublishPolicyFlag string
var factoryPublishFromFlag string
var factoryPublishSecretEnvFlags []string
var factoryPublishAllowUnverifiedFlag bool
var factoryPublishJSONFlag bool
var factoryPublishBranchPolicyFlag string
var factoryPublishBranchBaseFlag string
var factoryPublishBranchBranchFlag string
var factoryPublishBranchTitleFlag string
var factoryPublishBranchBodyFlag string
var factoryPublishBranchJSONFlag bool

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
  hal factory run .hal/prd-feature.md --sandbox --base main
  hal factory run .hal/prd-feature.md --sandbox --base main --sandbox-host worker-1 --sandbox-runtime rootless_podman`,
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

var factoryRecoverCmd = &cobra.Command{
	Use:   "recover <run-id>",
	Short: "Apply a stored sandbox recovery bundle locally",
	Args:  exactArgsValidation(1),
	Long: `Apply the recovery bundle collected from a stored sandbox factory run
to the current local repository. This command does not push a branch or create
a pull request.`,
	Example: `  hal factory recover run-20260620-001
  hal factory recover run-20260620-001 --json`,
	RunE: runFactoryRecover,
}

var factoryPublishCmd = &cobra.Command{
	Use:   "publish <run-id>",
	Short: "Publish a stored factory run",
	Args:  exactArgsValidation(1),
	Long: `Publish the branch associated with a stored factory run. Succeeded runs can
be published directly. Failed or incomplete runs require --allow-unverified so
the operator explicitly acknowledges the unverified result.`,
	Example: `  hal factory publish run-20260620-001 --policy push
  hal factory publish run-20260620-001 --allow-unverified --policy pr --json`,
	RunE: runFactoryPublish,
}

var factoryPublishBranchCmd = &cobra.Command{
	Use:    "_publish-branch",
	Hidden: true,
	Args:   noArgsValidation(),
	RunE:   runFactoryPublishBranch,
}

func init() {
	factoryRunCmd.Flags().StringVar(&factoryRunReportFlag, "report", "", "Start from an analysis report path")
	factoryRunCmd.Flags().StringVar(&factoryRunBaseFlag, "base", "", "Target base branch for follow-up review or CI")
	factoryRunCmd.Flags().StringArrayVar(&factoryRunSecretEnvFlags, "secret-env", nil, "Required environment variable secret for the run (repeatable)")
	factoryRunCmd.Flags().StringVar(&factoryRunCIPolicyFlag, "ci-policy", "", "CI policy for factory runs (required, skip-if-unavailable, disabled)")
	factoryRunCmd.Flags().BoolVar(&factoryRunNoCIFlag, "no-ci", false, "Alias for --ci-policy disabled")
	factoryRunCmd.Flags().StringVar(&factoryRunPublishFlag, "publish", "", "Host publish policy after factory execution (none, push, pr)")
	factoryRunCmd.Flags().StringVar(&factoryRunPublishFromFlag, "publish-from", factory.PublishRunnerHost, "Publish runner after factory execution (host, sandbox, auto)")
	factoryRunCmd.Flags().BoolVar(&factoryRunSandboxFlag, "sandbox", false, "Run the factory executor in a managed sandbox")
	factoryRunCmd.Flags().StringVar(&factoryRunSandboxNameFlag, "sandbox-name", "", "Sandbox name for --sandbox execution")
	factoryRunCmd.Flags().StringVar(&factoryRunSandboxHostFlag, sandboxHostFlagName, "", "Cached sandbox host ID for target selection")
	factoryRunCmd.Flags().StringVar(&factoryRunSandboxRuntimeFlag, sandboxRuntimeFlagName, "", "Cached runtime constraint for target selection (ssh_machine, rootless_podman, microvm)")
	factoryRunCmd.Flags().BoolVar(&factoryRunJSONFlag, "json", false, "Output machine-readable JSON (factory-run-v1 contract)")
	factoryListCmd.Flags().BoolVar(&factoryListJSONFlag, "json", false, "Output machine-readable JSON (factory-list-v1 contract)")
	factoryStatusCmd.Flags().BoolVar(&factoryStatusJSONFlag, "json", false, "Output machine-readable JSON (factory-status-v1 contract)")
	factoryArtifactsCmd.Flags().BoolVar(&factoryArtifactsJSONFlag, "json", false, "Output machine-readable JSON (factory-artifacts-v1 contract)")
	factoryLogsCmd.Flags().BoolVar(&factoryLogsJSONFlag, "json", false, "Output machine-readable JSON (factory-logs-v1 contract)")
	factoryOpenCmd.Flags().BoolVar(&factoryOpenExecFlag, "exec", false, "Execute the suggested inspection or resume command")
	factoryOpenCmd.Flags().BoolVar(&factoryOpenJSONFlag, "json", false, "Output machine-readable JSON (factory-open-v1 contract)")
	factoryRecoverCmd.Flags().BoolVar(&factoryRecoverJSONFlag, "json", false, "Output machine-readable JSON (factory-recover-v1 contract)")
	factoryPublishCmd.Flags().StringVar(&factoryPublishPolicyFlag, "policy", "", "Publish policy for stored run (push, pr)")
	factoryPublishCmd.Flags().StringVar(&factoryPublishFromFlag, "publish-from", factory.PublishRunnerHost, "Publish runner for stored run (host, sandbox, auto)")
	factoryPublishCmd.Flags().StringArrayVar(&factoryPublishSecretEnvFlags, "secret-env", nil, "Required environment variable secret for sandbox publish (repeatable)")
	factoryPublishCmd.Flags().BoolVar(&factoryPublishAllowUnverifiedFlag, "allow-unverified", false, "Allow publishing a failed or incomplete stored run")
	factoryPublishCmd.Flags().BoolVar(&factoryPublishJSONFlag, "json", false, "Output machine-readable JSON (factory-publish-v1 contract)")
	factoryPublishBranchCmd.Flags().StringVar(&factoryPublishBranchPolicyFlag, "policy", "", "Publish policy for current branch (push, pr)")
	factoryPublishBranchCmd.Flags().StringVar(&factoryPublishBranchBaseFlag, "base", "", "Target base branch for pull request creation")
	factoryPublishBranchCmd.Flags().StringVar(&factoryPublishBranchBranchFlag, "branch", "", "Expected current branch to publish")
	factoryPublishBranchCmd.Flags().StringVar(&factoryPublishBranchTitleFlag, "title", "", "Pull request title")
	factoryPublishBranchCmd.Flags().StringVar(&factoryPublishBranchBodyFlag, "body", "", "Pull request body")
	factoryPublishBranchCmd.Flags().BoolVar(&factoryPublishBranchJSONFlag, "json", false, "Output machine-readable JSON")
	configureFactoryTriggerCommand()
	configureFactoryQueueCommands()
	factoryCmd.AddCommand(factoryRunCmd)
	factoryCmd.AddCommand(factoryListCmd)
	factoryCmd.AddCommand(factoryStatusCmd)
	factoryCmd.AddCommand(factoryLogsCmd)
	factoryCmd.AddCommand(factoryOpenCmd)
	factoryCmd.AddCommand(factoryArtifactsCmd)
	factoryCmd.AddCommand(factoryRecoverCmd)
	factoryCmd.AddCommand(factoryPublishCmd)
	factoryCmd.AddCommand(factoryPublishBranchCmd)
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

type factoryRecoverDeps struct {
	defaultStore func() (factory.Store, error)
	workingDir   func() (string, error)
	now          func() time.Time
	runGit       func(context.Context, string, ...string) (string, error)
}

var defaultFactoryRecoverDeps = factoryRecoverDeps{
	defaultStore: factory.DefaultStore,
	workingDir:   os.Getwd,
	now:          time.Now,
	runGit:       runFactoryGitInDir,
}

type factoryPublishDeps struct {
	defaultStore           func() (factory.Store, error)
	workingDir             func() (string, error)
	now                    func() time.Time
	lookupEnv              func(string) (string, bool)
	runGit                 func(context.Context, string, ...string) (string, error)
	pushAndCreatePRInDir   func(context.Context, string, ci.PushOptions) (ci.PushResult, error)
	loadSandbox            func(string) (*sandbox.SandboxState, error)
	resolveProvider        func(string, string) (sandbox.Provider, error)
	runProviderExec        func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error
	runProviderExecIO      func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer, io.Writer) error
	runProviderExecWithEnv func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, map[string]string, io.Writer) error
	sandboxRequests        func(string, factory.RunRecord) []factory.SandboxArtifactRequest
}

var defaultFactoryPublishDeps = factoryPublishDeps{
	defaultStore:           factory.DefaultStore,
	workingDir:             os.Getwd,
	now:                    time.Now,
	lookupEnv:              os.LookupEnv,
	runGit:                 runFactoryGitInDir,
	pushAndCreatePRInDir:   ci.PushAndCreatePRInDir,
	loadSandbox:            sandbox.LoadActiveInstance,
	resolveProvider:        resolveProviderWithFallback,
	runProviderExec:        runFactorySandboxProviderExec,
	runProviderExecIO:      runFactorySandboxProviderExecIO,
	runProviderExecWithEnv: runFactorySandboxProviderExecWithEnv,
	sandboxRequests:        defaultFactorySandboxArtifactRequests,
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
	runProviderExecIO      func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer, io.Writer) error
	runProviderExecWithEnv func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, map[string]string, io.Writer) error
	cleanupSandbox         func(context.Context, factorySandboxCleanupRequest) error
	statusSnapshot         func(string) (factorySnapshotArtifact, error)
	doctorSnapshot         func(string) (factorySnapshotArtifact, error)
	sandboxCopier          factory.SandboxArtifactCopier
	sandboxRequests        func(string, factory.RunRecord) []factory.SandboxArtifactRequest
	runGit                 func(context.Context, string, ...string) (string, error)
	pushAndCreatePRInDir   func(context.Context, string, ci.PushOptions) (ci.PushResult, error)
}

type factoryRunPipelineRequest struct {
	RunID              string
	WorkDir            string
	Request            factoryRunRequest
	Record             factory.RunRecord
	Store              factory.Store
	Engine             string
	AttemptPolicy      autoFactoryAttemptPolicy
	MaxCommandRetries  int
	CIPolicy           string
	RuntimeStatePolicy string
	SkipCI             bool
	Now                func() time.Time
	RecordProgress     func(factoryRunProgressEvent) error
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
		return runFactorySandboxExecutorWithDeps(ctx, req, defaultFactorySandboxExecutorDeps)
	},
	loadVerify:             verify.LoadConfig,
	runVerify:              verify.Run,
	loadSandbox:            sandbox.LoadActiveInstance,
	resolveProvider:        resolveProviderWithFallback,
	runProviderExec:        runFactorySandboxProviderExec,
	runProviderExecIO:      runFactorySandboxProviderExecIO,
	runProviderExecWithEnv: runFactorySandboxProviderExecWithEnv,
	cleanupSandbox:         cleanupFactorySandbox,
	statusSnapshot:         defaultFactoryStatusSnapshot,
	doctorSnapshot:         defaultFactoryDoctorSnapshot,
	runGit:                 runFactoryGitInDir,
	pushAndCreatePRInDir:   ci.PushAndCreatePRInDir,
}

type factoryRunRequest struct {
	MarkdownPath   string
	ReportPath     string
	BaseBranch     string
	CIPolicy       string
	PublishPolicy  string
	PublishFrom    string
	Sandbox        bool
	SandboxName    string
	SandboxHostID  string
	SandboxRuntime string
	JSON           bool
	Secrets        []factory.RunSecretInput

	ResolvedSecrets []factory.ResolvedRunSecret
}

type factoryRunConfigFlagChanges struct {
	Base           bool
	Sandbox        bool
	SandboxName    bool
	SandboxHost    bool
	SandboxRuntime bool
	PublishFrom    bool
	SecretEnv      bool
}

type factoryPublishConfigFlagChanges struct {
	Policy      bool
	PublishFrom bool
	SecretEnv   bool
}

type factoryRunAutoRequest struct {
	WorkDir            string
	Args               []string
	ReportPath         string
	BaseBranch         string
	Engine             string
	AttemptPolicy      autoFactoryAttemptPolicy
	MaxCommandRetries  int
	CIPolicy           string
	RuntimeStatePolicy string
	SkipCI             bool
	Resume             bool
}

type factoryRunProgressEvent struct {
	Message  string
	Summary  string
	Metadata map[string]any
}

type factoryTimelineEvent struct {
	EventType                 string
	Message                   string
	Summary                   string
	Metadata                  map[string]any
	NetworkPolicyDecisionLogs []sandbox.SandboxNetworkPolicyDecisionLogRecord
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
	Policy       string `json:"policy,omitempty"`
	FixAttempts  int    `json:"fixAttempts,omitempty"`
	FixesApplied int    `json:"fixesApplied,omitempty"`
	BranchName   string `json:"branchName,omitempty"`
}

type factoryPublishOutcomeArtifact struct {
	Policy          string                   `json:"policy,omitempty"`
	Runner          string                   `json:"runner,omitempty"`
	FallbackFrom    string                   `json:"fallbackFrom,omitempty"`
	CredentialMode  string                   `json:"credentialMode,omitempty"`
	BranchName      string                   `json:"branchName,omitempty"`
	Commit          string                   `json:"commit,omitempty"`
	RecoveredBundle string                   `json:"recoveredBundle,omitempty"`
	Pushed          bool                     `json:"pushed"`
	PullRequest     *ci.PullRequest          `json:"pullRequest,omitempty"`
	Attempts        []factory.PublishAttempt `json:"attempts,omitempty"`
	Summary         string                   `json:"summary,omitempty"`
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
	RunID                 string                                                  `json:"runId"`
	Status                string                                                  `json:"status"`
	DisplayStatus         string                                                  `json:"displayStatus,omitempty"`
	PipelineStatus        string                                                  `json:"pipelineStatus,omitempty"`
	PublishStatus         string                                                  `json:"publishStatus,omitempty"`
	ExecutorMode          string                                                  `json:"executorMode,omitempty"`
	Engine                string                                                  `json:"engine,omitempty"`
	Source                factory.SourceMetadata                                  `json:"source"`
	RepoPath              string                                                  `json:"repoPath"`
	RepoRemote            string                                                  `json:"repoRemote"`
	BranchName            string                                                  `json:"branchName"`
	BaseBranch            string                                                  `json:"baseBranch"`
	Policy                *factory.FactoryPolicy                                  `json:"policy,omitempty"`
	PolicyDecisions       []factory.PolicyDecisionMetadata                        `json:"policyDecisions,omitempty"`
	SandboxName           string                                                  `json:"sandboxName,omitempty"`
	Sandbox               *factory.SandboxMetadata                                `json:"sandbox,omitempty"`
	SecurityReadinessGate *sandbox.SandboxSecurityCapabilityReadinessGateDecision `json:"securityReadinessGate,omitempty"`
	CurrentStep           string                                                  `json:"currentStep"`
	CreatedAt             time.Time                                               `json:"createdAt"`
	UpdatedAt             time.Time                                               `json:"updatedAt"`
	FinishedAt            *time.Time                                              `json:"finishedAt,omitempty"`
	Secrets               []factory.RunSecretMetadata                             `json:"secrets,omitempty"`
	Artifacts             []FactoryArtifactSummary                                `json:"artifacts,omitempty"`
	Verification          *factory.VerificationRecord                             `json:"verification,omitempty"`
	Telemetry             *factory.RunTelemetry                                   `json:"telemetry,omitempty"`
	Failure               *factory.FailureSummary                                 `json:"failure,omitempty"`
	Handoff               *factory.HandoffSummary                                 `json:"handoff,omitempty"`
	PostRun               *factory.PostRunState                                   `json:"postRun,omitempty"`
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

// FactoryRecoverResponse is the machine-readable JSON output for
// hal factory recover <run-id> --json.
type FactoryRecoverResponse struct {
	ContractVersion string `json:"contractVersion"`
	OK              bool   `json:"ok"`
	RunID           string `json:"runId"`
	Status          string `json:"status"`
	BranchName      string `json:"branchName"`
	RecoveredBundle string `json:"recoveredBundle,omitempty"`
	Error           string `json:"error,omitempty"`
}

// FactoryPublishResponse is the machine-readable JSON output for
// hal factory publish <run-id> --json.
type FactoryPublishResponse struct {
	ContractVersion string                   `json:"contractVersion"`
	OK              bool                     `json:"ok"`
	RunID           string                   `json:"runId"`
	Status          string                   `json:"status"`
	DisplayStatus   string                   `json:"displayStatus,omitempty"`
	PipelineStatus  string                   `json:"pipelineStatus,omitempty"`
	PublishStatus   string                   `json:"publishStatus,omitempty"`
	Policy          string                   `json:"policy"`
	PublishFrom     string                   `json:"publishFrom,omitempty"`
	Runner          string                   `json:"runner,omitempty"`
	AllowUnverified bool                     `json:"allowUnverified,omitempty"`
	BranchName      string                   `json:"branchName"`
	PullRequestURL  string                   `json:"pullRequestUrl,omitempty"`
	Artifacts       []FactoryArtifactSummary `json:"artifacts,omitempty"`
	Error           string                   `json:"error,omitempty"`
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
	RunID                 string                                                  `json:"runId"`
	Status                string                                                  `json:"status"`
	DisplayStatus         string                                                  `json:"displayStatus,omitempty"`
	PipelineStatus        string                                                  `json:"pipelineStatus,omitempty"`
	PublishStatus         string                                                  `json:"publishStatus,omitempty"`
	Source                factory.SourceMetadata                                  `json:"source"`
	RepoPath              string                                                  `json:"repoPath"`
	RepoRemote            string                                                  `json:"repoRemote"`
	BranchName            string                                                  `json:"branchName"`
	BaseBranch            string                                                  `json:"baseBranch"`
	SandboxName           string                                                  `json:"sandboxName,omitempty"`
	SecurityReadinessGate *sandbox.SandboxSecurityCapabilityReadinessGateDecision `json:"securityReadinessGate,omitempty"`
	CurrentStep           string                                                  `json:"currentStep"`
	CreatedAt             time.Time                                               `json:"createdAt"`
	UpdatedAt             time.Time                                               `json:"updatedAt"`
	FinishedAt            *time.Time                                              `json:"finishedAt,omitempty"`
	ArtifactCount         int                                                     `json:"artifactCount"`
	Telemetry             *factory.RunTelemetry                                   `json:"telemetry,omitempty"`
	Failure               *factory.FailureSummary                                 `json:"failure,omitempty"`
	PostRun               *factory.PostRunState                                   `json:"postRun,omitempty"`
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

	countingOut := newFactoryCountingWriter(out)
	err = runFactoryRunWithDeps(ctx, ".", req, countingOut, defaultFactoryRunDeps)
	return suppressFactoryJSONRenderedError(err, req.JSON, countingOut)
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
	if err := applyFactoryRunPolicyOverrides(&creationPolicy, req); err != nil {
		return failFactoryRunCreationWithRedactor(store, record, out, req.JSON, deps.now(), err, nil, initialRedactor)
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

	if req.Sandbox && strings.TrimSpace(req.BaseBranch) == "" {
		return failFactoryRunSetup(store, record, deps.now(), fmt.Errorf("--base is required when --sandbox is set"), factory.RunSecretRedactor{})
	}
	var sandboxSecurity sandbox.SecurityEvaluationRequest
	if req.Sandbox {
		var err error
		sandboxSecurity, err = loadConfiguredSandboxSecurityRequest(dir, req.SandboxRuntime)
		if err != nil {
			return failFactoryRunSetup(store, record, deps.now(), fmt.Errorf("load factory sandbox security config: %w", err), factory.RunSecretRedactor{})
		}
		if factoryRunStrictDefaultSandboxReadinessGateApplies(req, policy) {
			if err := enforceFactoryRunStrictDefaultSandboxReadinessGate(store, deps, &record, factory.RunSecretRedactor{}); err != nil {
				failedRecord := record
				if stored, loadErr := store.LoadRun(record.RunID); loadErr == nil && stored != nil {
					failedRecord = *stored
				}
				return factoryRunExecutionResult{Record: failedRecord, Render: true}, err
			}
		}
	}

	req, record, err := resolveFactoryRunExecutionSecrets(req, record, deps)
	redactor := factory.NewRunSecretRedactor(req.ResolvedSecrets)
	if err != nil {
		redactor = factory.NewRunSecretRedactor(resolveFactoryRunRedactionSecrets(req.Secrets, deps.lookupEnv))
		return failFactoryRunSetup(store, record, deps.now(), err, redactor)
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
		RunID:              runningRecord.RunID,
		WorkDir:            dir,
		Request:            req,
		Record:             runningRecord,
		Store:              store,
		Engine:             engineName,
		AttemptPolicy:      autoFactoryAttemptPolicyFromFactoryPolicy(policy),
		MaxCommandRetries:  policy.MaxCommandRetries,
		CIPolicy:           policy.CIPolicy,
		RuntimeStatePolicy: compound.RuntimeStatePolicyCheckpointFactoryState,
		SkipCI:             factoryPolicySkipsCI(policy),
		Now:                deps.now,
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
		remoteAuto.MaxCommandRetries = policy.MaxCommandRetries
		remoteAuto.CIPolicy = policy.CIPolicy
		remoteAuto.RuntimeStatePolicy = compound.RuntimeStatePolicyCheckpointFactoryState
		remoteAuto.SkipCI = factoryPolicySkipsCI(policy)
		runErr = deps.runSandbox(ctx, factorySandboxExecutorRequest{
			ProjectDir:                dir,
			RunRecord:                 runningRecord,
			ResolvedSecrets:           req.ResolvedSecrets,
			RemoteAuto:                remoteAuto,
			SandboxName:               req.SandboxName,
			SandboxHostID:             req.SandboxHostID,
			SandboxRuntime:            req.SandboxRuntime,
			Security:                  sandboxSecurity,
			SecurityReadinessGateMode: policy.EffectiveSecurityReadinessGatePolicyMode(),
			RemoteOutput:              remoteOutput,
			DeferSuccessCleanup:       factoryRunDefersSandboxSuccessCleanup(policy),
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
		if currentRecord, loadErr := store.LoadRun(runningRecord.RunID); loadErr == nil && currentRecord != nil {
			failedRecord = *currentRecord
		}
		collectSandboxArtifacts := !sandboxArtifactsCollected && failedRecord.ExecutorMode == factory.ExecutorModeSandbox
		if artifactRecord, artifactErr := recordFactoryRunArtifacts(ctx, store, runningRecord.RunID, dir, req, artifactSnapshot, failedAt, deps, collectSandboxArtifacts, redactor); artifactErr != nil {
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
			return factoryRunExecutionResult{Record: failedRecord, Render: true}, redactFactoryRunJoinedError(runErr, recordErrs, redactor)
		}
		return factoryRunExecutionResult{Record: failedRecord, Render: true}, runErr
	}
	if req.Sandbox {
		if reloadedRecord, loadErr := store.LoadRun(runningRecord.RunID); loadErr != nil {
			return factoryRunExecutionResult{Record: runningRecord}, fmt.Errorf("reload factory run after sandbox execution: %w", loadErr)
		} else if reloadedRecord != nil {
			runningRecord = *reloadedRecord
		}
	}

	pipelineCompletedAt := deps.now()
	if err := recordFactoryRunPipelineSucceeded(store, runningRecord.RunID, pipelineCompletedAt); err != nil {
		return factoryRunExecutionResult{Record: runningRecord}, err
	}
	collectSandboxArtifacts := !sandboxArtifactsCollected && deps.sandboxCopier != nil
	completedRecord, err := recordFactoryRunArtifacts(ctx, store, runningRecord.RunID, dir, req, artifactSnapshot, pipelineCompletedAt, deps, collectSandboxArtifacts, redactor)
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
			return factoryRunExecutionResult{Record: failedRecord}, redactFactoryRunJoinedError(err, recordErrs, redactor)
		}
		return factoryRunExecutionResult{Record: failedRecord, Render: true}, err
	}
	if req.Sandbox && !sandboxArtifactsCollected && (!factoryRunDefersSandboxSuccessCleanup(policy) || factoryPublishRequiresPrePublishSandboxArtifacts(policy, req)) {
		if err := collectAndStoreFactorySandboxArtifacts(ctx, store, dir, req, completedRecord, deps); err != nil {
			return failFactoryRunAfterArtifactCollectionFailure(ctx, store, dir, req, out, completedRecord, deps, policy, err)
		}
		sandboxArtifactsCollected = true
		if reloadedRecord, loadErr := store.LoadRun(completedRecord.RunID); loadErr != nil {
			return factoryRunExecutionResult{Record: completedRecord}, fmt.Errorf("reload factory run after sandbox artifact collection: %w", loadErr)
		} else if reloadedRecord != nil {
			completedRecord = *reloadedRecord
		}
	}
	completedRecord, err = publishFactoryRunAfterVerifiedSuccess(ctx, store, dir, req, completedRecord, deps, policy, redactor, "automatic", false)
	if err != nil {
		failedAt := deps.now()
		failedRecord, failureErr := markFactoryRunFailedWithRedactor(store, completedRecord, failedAt, err, redactor)
		var recordErrs []error
		if failureErr != nil {
			recordErrs = append(recordErrs, failureErr)
		}
		if eventErr := recordFactoryRunPublishFailedWithRedactor(store, failedRecord.RunID, failedAt, err, redactor); eventErr != nil {
			recordErrs = append(recordErrs, fmt.Errorf("record factory publish failure event: %w", eventErr))
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
			return factoryRunExecutionResult{Record: failedRecord}, redactFactoryRunJoinedError(err, recordErrs, redactor)
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
			return factoryRunExecutionResult{Record: failedRecord}, redactFactoryRunJoinedError(err, recordErrs, redactor)
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

func factoryRunStrictDefaultSandboxReadinessGateApplies(req factoryRunRequest, policy factory.FactoryPolicy) bool {
	return req.Sandbox &&
		policy.EffectiveSecurityReadinessGatePolicyMode() == sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict &&
		strings.TrimSpace(req.SandboxHostID) == "" &&
		strings.TrimSpace(req.SandboxRuntime) == ""
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
	customRunProviderExec := deps.runProviderExec != nil && !sameFactoryRunFunc(deps.runProviderExec, defaultFactoryRunDeps.runProviderExec)
	customProviderExec := factoryRunProviderExecDepsAreCustom(deps)
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
	if deps.runProviderExecIO == nil {
		if customRunProviderExec {
			runProviderExec := deps.runProviderExec
			deps.runProviderExecIO = func(ctx context.Context, provider sandbox.Provider, info *sandbox.ConnectInfo, args []string, stdout, _ io.Writer) error {
				return runProviderExec(ctx, provider, info, args, stdout)
			}
		} else {
			deps.runProviderExecIO = defaultFactoryRunDeps.runProviderExecIO
		}
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
	if deps.runGit == nil {
		deps.runGit = defaultFactoryRunDeps.runGit
	}
	if deps.pushAndCreatePRInDir == nil {
		deps.pushAndCreatePRInDir = defaultFactoryRunDeps.pushAndCreatePRInDir
	}
	if deps.sandboxRequests == nil {
		if customProviderExec && deps.sandboxCopier == nil {
			deps.sandboxRequests = func(string, factory.RunRecord) []factory.SandboxArtifactRequest { return nil }
		} else {
			deps.sandboxRequests = defaultFactorySandboxArtifactRequests
		}
	}
	return deps
}

func factoryRunProviderExecDepsAreCustom(deps factoryRunDeps) bool {
	return (deps.runProviderExec != nil && !sameFactoryRunFunc(deps.runProviderExec, defaultFactoryRunDeps.runProviderExec)) ||
		(deps.runProviderExecIO != nil && !sameFactoryRunFunc(deps.runProviderExecIO, defaultFactoryRunDeps.runProviderExecIO)) ||
		(deps.runProviderExecWithEnv != nil && !sameFactoryRunFunc(deps.runProviderExecWithEnv, defaultFactoryRunDeps.runProviderExecWithEnv))
}

func sameFactoryRunFunc(left, right any) bool {
	if left == nil || right == nil {
		return left == right
	}
	leftValue := reflect.ValueOf(left)
	rightValue := reflect.ValueOf(right)
	if leftValue.Kind() != reflect.Func || rightValue.Kind() != reflect.Func {
		return false
	}
	if leftValue.IsNil() || rightValue.IsNil() {
		return leftValue.IsNil() && rightValue.IsNil()
	}
	return leftValue.Pointer() == rightValue.Pointer()
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
	branchName, err := resolveFactoryRunBranchName(dir, req, deps)
	if err != nil {
		return factory.RunRecord{}, err
	}
	repoRemote, err := deps.repoRemote(dir)
	if err != nil {
		return factory.RunRecord{}, fmt.Errorf("resolve repository remote: %w", err)
	}

	record := factory.RunRecord{
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
	}
	if req.Sandbox {
		record.SandboxName, record.Sandbox = factorySandboxMetadataFromName(strings.TrimSpace(req.SandboxName))
	}
	return record, nil
}

func resolveFactoryRunBranchName(dir string, req factoryRunRequest, deps factoryRunDeps) (string, error) {
	if markdownPath := strings.TrimSpace(req.MarkdownPath); markdownPath != "" {
		resolvedPath := markdownPath
		if !filepath.IsAbs(resolvedPath) {
			resolvedPath = filepath.Join(dir, resolvedPath)
		}
		absPath, err := filepath.Abs(resolvedPath)
		if err != nil {
			return "", fmt.Errorf("resolve markdown PRD path %s: %w", markdownPath, err)
		}
		content, err := os.ReadFile(absPath)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return "", fmt.Errorf("read markdown PRD %s: %w", markdownPath, err)
			}
		} else {
			branchName := prd.ResolveMarkdownBranchName(string(content), absPath)
			if branchName != "" {
				return branchName, nil
			}
		}
	}

	branchName, err := deps.currentBranch(dir)
	if err != nil {
		return "", fmt.Errorf("resolve current branch: %w", err)
	}
	return branchName, nil
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
	return !policy.PRCreationAllowed || strings.TrimSpace(policy.CIPolicy) == factory.CIPolicyDisabled
}

func applyFactoryRunPolicyOverrides(policy *factory.FactoryPolicy, req factoryRunRequest) error {
	if policy == nil {
		return fmt.Errorf("factory policy is nil")
	}
	if ciPolicy := strings.TrimSpace(req.CIPolicy); ciPolicy != "" {
		policy.CIPolicy = ciPolicy
	}
	if publishPolicy := strings.TrimSpace(req.PublishPolicy); publishPolicy != "" {
		policy.PublishPolicy = publishPolicy
	}
	return policy.Validate()
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
	if err := collectAndStoreFactorySandboxArtifactRequestsWithProviderExec(ctx, store, req, record, deps, target, provider, requests); err != nil {
		return fmt.Errorf("collect sandbox factory artifacts before cleanup: %w", err)
	}
	return nil
}

func collectAndStoreFactorySandboxArtifactRequestsWithProviderExec(ctx context.Context, store factory.Store, req factoryRunRequest, record factory.RunRecord, deps factoryRunDeps, target *sandbox.SandboxState, provider sandbox.Provider, requests []factory.SandboxArtifactRequest) error {
	requests, err := factorySandboxRemoteWorkspaceArtifactRequests(record, requests)
	if err != nil {
		return err
	}
	copier := factoryProviderExecSandboxArtifactCopier{
		provider:          provider,
		connectInfo:       sandbox.ConnectInfoFromState(target),
		baseDir:           factorySandboxRemoteWorkspaceDir(record),
		runProviderExec:   deps.runProviderExec,
		runProviderExecIO: deps.runProviderExecIO,
	}
	redactor := factory.NewRunSecretRedactor(req.ResolvedSecrets)
	if _, err := factory.CollectSandboxArtifactsWithRedactor(ctx, store, record.RunID, &copier, requests, redactor); err != nil {
		_ = recordFactoryRunArtifactSyncFailedWithRedactor(store, record.RunID, factoryRunDepsNow(deps), err, redactor)
		return err
	}
	return nil
}

func resolveFactorySandboxArtifactCollectionTarget(dir string, record factory.RunRecord, deps factoryRunDeps) (*sandbox.SandboxState, sandbox.Provider, error) {
	name := strings.TrimSpace(record.SandboxName)
	if name == "" && record.Sandbox != nil {
		name = strings.TrimSpace(record.Sandbox.Name)
	}
	if name == "" {
		return nil, nil, nil
	}
	target, err := deps.loadSandbox(name)
	if err != nil {
		return nil, nil, fmt.Errorf("load factory sandbox for artifact collection %q: %w", name, err)
	}
	if target == nil {
		return nil, nil, nil
	}
	providerName := strings.TrimSpace(target.Provider)
	if providerName == "" && record.Sandbox != nil {
		providerName = strings.TrimSpace(record.Sandbox.Provider)
	}
	if providerName == "" {
		return nil, nil, fmt.Errorf("resolve sandbox provider for artifact collection %q: provider is required", name)
	}
	provider, err := deps.resolveProvider(dir, providerName)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve sandbox provider %q for artifact collection: %w", providerName, err)
	}
	return target, provider, nil
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
		return recordFactoryRunVerificationOutcome(store, dir, updatedRecord, startedAt, finishedAt, result, policy, redactor, false, "")
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

	artifactDir, cleanupArtifacts, err := createFactoryVerificationArtifactDir(store, record.RunID)
	if err != nil {
		return record, deps.now(), fmt.Errorf("prepare factory verification artifacts: %w", err)
	}
	defer cleanupArtifacts()
	cfg.ArtifactDir = artifactDir

	result, err := deps.runVerify(ctx, cfg)
	finishedAt := deps.now()
	if err != nil {
		return record, finishedAt, fmt.Errorf("run verification: %w", err)
	}
	if result == nil {
		return record, finishedAt, fmt.Errorf("run verification: no result")
	}

	return recordFactoryRunVerificationOutcome(store, dir, record, startedAt, finishedAt, result, policy, redactor, true, artifactDir)
}

func recordFactoryRunVerificationOutcome(store factory.Store, dir string, record factory.RunRecord, startedAt, finishedAt time.Time, result *verify.Result, policy factory.FactoryPolicy, redactor factory.RunSecretRedactor, startedRecorded bool, localArtifactDir string) (factory.RunRecord, time.Time, error) {
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
	if !factoryRunUsesSandboxVerification(record) {
		if err := collectAndStoreFactoryVerificationArtifacts(store, dir, record.RunID, result.Artifacts, localArtifactDir, redactor); err != nil {
			return factory.RunRecord{}, finishedAt, err
		}
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
			if err := recordFactoryRunVerificationAdvisoryFailedWithRedactor(store, record.RunID, finishedAt, newFactoryRunVerificationFailure(result), redactor); err != nil {
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

func createFactoryVerificationArtifactDir(store factory.Store, runID string) (string, func(), error) {
	tmpRoot := ""
	if root := strings.TrimSpace(store.Root()); root != "" {
		tmpRoot = filepath.Join(root, "tmp")
		if err := os.MkdirAll(tmpRoot, 0700); err != nil {
			return "", func() {}, err
		}
	}

	prefix := "verify-"
	if safeRunID := sanitizeFactoryArtifactPathComponent(runID); safeRunID != "" {
		prefix = safeRunID + "-verify-"
	}
	dir, err := os.MkdirTemp(tmpRoot, prefix)
	if err != nil {
		return "", func() {}, err
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
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
	verifyScript := "set -eu\ncd " + shellQuote(workspaceDir) + "\n" + factorySandboxRemoteHalScript([]string{"verify", "--json"}) + " 2>/tmp/hal-factory-verify-stderr"
	return []string{"sh", "-lc", verifyScript}, nil
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
		artifactPath := strings.TrimSpace(artifact.Path)
		if artifactPath == "" {
			continue
		}
		displayPath := path.Clean(filepath.ToSlash(artifactPath))
		remotePath := displayPath
		if !path.IsAbs(remotePath) {
			remotePath = path.Join(filepath.ToSlash(workspaceDir), remotePath)
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
			Type:       factoryArtifactTypeForPath(artifactPath),
			RemotePath: path.Clean(remotePath),
			Path:       displayPath,
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
		provider:          provider,
		connectInfo:       sandbox.ConnectInfoFromState(target),
		baseDir:           workspaceDir,
		runProviderExec:   deps.runProviderExec,
		runProviderExecIO: deps.runProviderExecIO,
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
	provider          sandbox.Provider
	connectInfo       *sandbox.ConnectInfo
	baseDir           string
	runProviderExec   func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error
	runProviderExecIO func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer, io.Writer) error
}

func (c *factoryProviderExecSandboxArtifactCopier) CopyFile(ctx context.Context, remotePath, localPath string) error {
	resolvedRemotePath, err := c.resolveSandboxArtifactPath(remotePath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(localPath), 0o700); err != nil {
		return fmt.Errorf("create sandbox artifact destination: %w", err)
	}

	file, err := os.OpenFile(localPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create sandbox artifact file: %w", err)
	}
	var stderr bytes.Buffer
	runErr := c.run(ctx, factorySandboxArtifactPythonCommand(factorySandboxArtifactCopyFilePythonScript, resolvedRemotePath.baseDir, resolvedRemotePath.relativePath), file, &stderr)
	closeErr := file.Close()
	if runErr != nil {
		errorOutput := stderr.String()
		if errorOutput == "" {
			errorOutput = readFactorySandboxArtifactErrorOutput(localPath)
		}
		_ = os.Remove(localPath)
		return factorySandboxArtifactCopyError(resolvedRemotePath.resolvedPath, errorOutput, runErr)
	}
	if closeErr != nil {
		_ = os.Remove(localPath)
		return fmt.Errorf("write sandbox artifact file: %w", closeErr)
	}
	return nil
}

func (c *factoryProviderExecSandboxArtifactCopier) CopyDir(ctx context.Context, remotePath, localPath string) error {
	resolvedRemotePath, err := c.resolveSandboxArtifactPath(remotePath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(localPath), 0o700); err != nil {
		return fmt.Errorf("create sandbox artifact destination: %w", err)
	}

	tarFile, err := os.CreateTemp(filepath.Dir(localPath), "sandbox-artifact-*.tar")
	if err != nil {
		return fmt.Errorf("create sandbox artifact archive: %w", err)
	}
	tarPath := tarFile.Name()
	defer os.Remove(tarPath)

	var stderr bytes.Buffer
	runErr := c.run(ctx, factorySandboxArtifactPythonCommand(factorySandboxArtifactCopyDirPythonScript, resolvedRemotePath.baseDir, resolvedRemotePath.relativePath), tarFile, &stderr)
	closeErr := tarFile.Close()
	if runErr != nil {
		errorOutput := stderr.String()
		if errorOutput == "" {
			errorOutput = readFactorySandboxArtifactErrorOutput(tarPath)
		}
		_ = os.RemoveAll(localPath)
		return factorySandboxArtifactCopyError(resolvedRemotePath.resolvedPath, errorOutput, runErr)
	}
	if closeErr != nil {
		_ = os.RemoveAll(localPath)
		return fmt.Errorf("write sandbox artifact archive: %w", closeErr)
	}
	if err := extractFactorySandboxArtifactTar(tarPath, localPath); err != nil {
		_ = os.RemoveAll(localPath)
		return err
	}
	return nil
}

func (c *factoryProviderExecSandboxArtifactCopier) resolveSandboxArtifactPath(remotePath string) (factorySandboxArtifactRemotePath, error) {
	return (&factorySandboxArtifactCopier{baseDir: c.baseDir}).resolveSandboxArtifactPath(remotePath)
}

func (c *factoryProviderExecSandboxArtifactCopier) run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if c.runProviderExecIO != nil {
		return c.runProviderExecIO(ctx, c.provider, c.connectInfo, args, stdout, stderr)
	}
	if c.runProviderExec == nil {
		return fmt.Errorf("sandbox provider exec runner is required")
	}
	return c.runProviderExec(ctx, c.provider, c.connectInfo, args, stdout)
}

func readFactorySandboxArtifactErrorOutput(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
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
			Policy:       strings.TrimSpace(state.CI.Policy),
			FixAttempts:  state.CI.FixAttempts,
			FixesApplied: state.CI.FixesApplied,
			BranchName:   strings.TrimSpace(state.BranchName),
		}, map[string]any{
			"outcomeKind": "ci",
			"status":      strings.TrimSpace(state.CI.Status),
			"policy":      strings.TrimSpace(state.CI.Policy),
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
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	return parsed.String()
}

func markFactoryRunSucceeded(store factory.Store, record factory.RunRecord, now time.Time) (factory.RunRecord, error) {
	return markFactoryRunSucceededWithRedactor(store, record, now, factory.RunSecretRedactor{})
}

func markFactoryRunSucceededWithRedactor(store factory.Store, record factory.RunRecord, now time.Time, redactor factory.RunSecretRedactor) (factory.RunRecord, error) {
	finishedAt := now.UTC()
	record.Status = factoryRunSucceededStatus(record)
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

func factoryRunSucceededStatus(record factory.RunRecord) string {
	for _, artifact := range record.Artifacts {
		if artifact.Summary == nil {
			continue
		}
		if outcomeKind, _ := artifact.Summary["outcomeKind"].(string); strings.TrimSpace(outcomeKind) != "ci" {
			continue
		}
		status, _ := artifact.Summary["status"].(string)
		switch strings.TrimSpace(status) {
		case "unavailable", "skipped":
			return factory.RunStatusSucceededWithWarnings
		}
	}
	return factory.RunStatusSucceeded
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
	failure.Step = redactFactoryString(failure.Step, redactor)
	failure.Category = redactFactoryString(failure.Category, redactor)
	failure.Message = redactFactoryString(failure.Message, redactor)
	failure.SuggestedCommand = redactFactoryString(failure.SuggestedCommand, redactor)
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
	message := redactFactoryString(err.Error(), redactor)
	if message == err.Error() {
		return err
	}
	return factoryRunRedactedError{
		message: message,
		cause:   err,
	}
}

func redactFactoryRunJoinedError(primary error, recordErrs []error, redactor factory.RunSecretRedactor) error {
	return redactFactoryRunError(errors.Join(append([]error{primary}, recordErrs...)...), redactor)
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

func factoryPublishPolicyRequiresHostArtifacts(policy factory.FactoryPolicy) bool {
	return strings.TrimSpace(policy.PublishPolicy) == factory.PublishPolicyPush ||
		strings.TrimSpace(policy.PublishPolicy) == factory.PublishPolicyPR
}

func factoryPublishRequiresPrePublishSandboxArtifacts(policy factory.FactoryPolicy, req factoryRunRequest) bool {
	if !factoryPublishPolicyRequiresHostArtifacts(policy) {
		return false
	}
	publishFrom := strings.TrimSpace(req.PublishFrom)
	if publishFrom == "" {
		publishFrom = factory.PublishRunnerHost
	}
	return publishFrom == factory.PublishRunnerHost
}

func publishFactoryRunAfterVerifiedSuccess(ctx context.Context, store factory.Store, dir string, req factoryRunRequest, record factory.RunRecord, deps factoryRunDeps, policy factory.FactoryPolicy, redactor factory.RunSecretRedactor, source string, allowUnverified bool) (factory.RunRecord, error) {
	publishPolicy := strings.TrimSpace(policy.PublishPolicy)
	if publishPolicy == "" || publishPolicy == factory.PublishPolicyNone {
		return record, nil
	}
	if publishPolicy != factory.PublishPolicyPush && publishPolicy != factory.PublishPolicyPR {
		return record, fmt.Errorf("factory publish policy %q is unsupported", publishPolicy)
	}
	publishFrom := strings.TrimSpace(req.PublishFrom)
	if publishFrom == "" {
		publishFrom = factory.PublishRunnerHost
	}
	normalizedPublishFrom, err := factory.ValidatePublishRunner(publishFrom)
	if err != nil {
		return record, err
	}
	publishFrom = normalizedPublishFrom

	if err := recordFactoryRunPublishStarted(store, record.RunID, deps.now(), publishPolicy, publishFrom); err != nil {
		return record, err
	}

	result, err := publishFactoryRunWithRunner(ctx, store, dir, req, record, deps, policy, publishFrom, publishPolicy, redactor)
	if err != nil {
		return record, err
	}
	updatedRecord, err := recordFactoryPublishOutcomeArtifact(store, record, publishPolicy, result.RecoveredBundle, result.Push, redactor, source, allowUnverified, deps.now(), result.Runner, result.FallbackFrom, result.CredentialMode, result.Commit, result.Attempts)
	if err != nil {
		return record, err
	}
	if err := recordFactoryRunPublishSucceeded(store, updatedRecord.RunID, deps.now(), publishPolicy, result.Runner, result.Push); err != nil {
		return updatedRecord, err
	}
	return updatedRecord, nil
}

type factoryPublishRunnerResult struct {
	Runner          string
	FallbackFrom    string
	CredentialMode  string
	Commit          string
	RecoveredBundle string
	Push            ci.PushResult
	Attempts        []factory.PublishAttempt
}

func publishFactoryRunWithRunner(ctx context.Context, store factory.Store, dir string, req factoryRunRequest, record factory.RunRecord, deps factoryRunDeps, policy factory.FactoryPolicy, publishFrom, publishPolicy string, redactor factory.RunSecretRedactor) (factoryPublishRunnerResult, error) {
	switch publishFrom {
	case factory.PublishRunnerHost:
		return publishFactoryRunWithHostRunner(ctx, store, dir, req, record, deps, policy, publishPolicy, nil)
	case factory.PublishRunnerSandbox:
		return publishFactoryRunWithSandboxRunner(ctx, dir, req, record, deps, publishPolicy, nil)
	case factory.PublishRunnerAuto:
		if !req.Sandbox {
			return publishFactoryRunWithHostRunner(ctx, store, dir, req, record, deps, policy, publishPolicy, nil)
		}
		startedAt := deps.now()
		sandboxResult, err := publishFactoryRunWithSandboxRunner(ctx, dir, req, record, deps, publishPolicy, nil)
		if err == nil {
			return sandboxResult, nil
		}
		completedAt := deps.now()
		failedAttempt := factory.PublishAttempt{
			Runner:      factory.PublishRunnerSandbox,
			Status:      factory.RunStatusFailed,
			Error:       redactFactoryString(err.Error(), redactor),
			StartedAt:   &startedAt,
			CompletedAt: &completedAt,
		}
		return publishFactoryRunWithHostRunner(ctx, store, dir, req, record, deps, policy, publishPolicy, []factory.PublishAttempt{failedAttempt})
	default:
		return factoryPublishRunnerResult{}, fmt.Errorf("factory publish runner %q is unsupported", publishFrom)
	}
}

func publishFactoryRunWithHostRunner(ctx context.Context, store factory.Store, dir string, req factoryRunRequest, record factory.RunRecord, deps factoryRunDeps, policy factory.FactoryPolicy, publishPolicy string, priorAttempts []factory.PublishAttempt) (factoryPublishRunnerResult, error) {
	startedAt := deps.now()
	updatedRecord, err := ensureFactorySandboxRecoveryBundleForPublish(ctx, store, dir, req, record, deps, policy)
	if err != nil {
		return factoryPublishRunnerResult{}, err
	}
	record = updatedRecord

	branchName := strings.TrimSpace(record.BranchName)
	recoveredBundle := ""
	if req.Sandbox {
		appliedBranch, bundlePath, err := applyFactorySandboxRecoveryBundle(ctx, store, dir, record, deps)
		if err != nil {
			return factoryPublishRunnerResult{}, err
		}
		branchName = appliedBranch
		recoveredBundle = bundlePath
	}
	if branchName == "" {
		return factoryPublishRunnerResult{}, fmt.Errorf("factory publish requires a branch name")
	}

	result, err := publishFactoryRunBranch(ctx, dir, req, record, deps, publishPolicy, branchName)
	completedAt := deps.now()
	if err != nil {
		return factoryPublishRunnerResult{}, err
	}
	attempts := append([]factory.PublishAttempt(nil), priorAttempts...)
	attempts = append(attempts, factory.PublishAttempt{
		Runner:      factory.PublishRunnerHost,
		Status:      factory.RunStatusSucceeded,
		StartedAt:   &startedAt,
		CompletedAt: &completedAt,
	})
	out := factoryPublishRunnerResult{
		Runner:          factory.PublishRunnerHost,
		RecoveredBundle: recoveredBundle,
		Push:            result,
		Attempts:        attempts,
	}
	if len(priorAttempts) > 0 {
		out.FallbackFrom = factory.PublishRunnerSandbox
	}
	return out, nil
}

func publishFactoryRunWithSandboxRunner(ctx context.Context, dir string, req factoryRunRequest, record factory.RunRecord, deps factoryRunDeps, publishPolicy string, priorAttempts []factory.PublishAttempt) (factoryPublishRunnerResult, error) {
	if !req.Sandbox && record.ExecutorMode != factory.ExecutorModeSandbox {
		return factoryPublishRunnerResult{}, fmt.Errorf("--publish-from sandbox requires a sandbox-backed factory run")
	}
	if deps.loadSandbox == nil {
		return factoryPublishRunnerResult{}, fmt.Errorf("factory sandbox publish requires sandbox load dependency")
	}
	if deps.resolveProvider == nil {
		return factoryPublishRunnerResult{}, fmt.Errorf("factory sandbox publish requires provider dependency")
	}
	if deps.runProviderExecWithEnv == nil {
		return factoryPublishRunnerResult{}, fmt.Errorf("factory sandbox publish requires provider exec dependency")
	}
	sandboxName := factoryRunSandboxName(record)
	if sandboxName == "" {
		sandboxName = strings.TrimSpace(req.SandboxName)
	}
	if sandboxName == "" {
		return factoryPublishRunnerResult{}, fmt.Errorf("factory sandbox publish requires sandbox metadata")
	}
	target, err := deps.loadSandbox(sandboxName)
	if err != nil {
		return factoryPublishRunnerResult{}, fmt.Errorf("load sandbox %q for publish: %w", sandboxName, err)
	}
	if target == nil {
		return factoryPublishRunnerResult{}, fmt.Errorf("load sandbox %q for publish: not found", sandboxName)
	}
	provider, err := deps.resolveProvider(dir, target.Provider)
	if err != nil {
		return factoryPublishRunnerResult{}, fmt.Errorf("resolve sandbox provider %q for publish: %w", target.Provider, err)
	}
	branchName := strings.TrimSpace(record.BranchName)
	if branchName == "" {
		return factoryPublishRunnerResult{}, fmt.Errorf("factory sandbox publish requires a branch name")
	}
	args, err := factorySandboxRemotePublishArgs(record, req, publishPolicy, branchName)
	if err != nil {
		return factoryPublishRunnerResult{}, err
	}
	startedAt := deps.now()
	var out bytes.Buffer
	execErr := deps.runProviderExecWithEnv(ctx, provider, sandbox.ConnectInfoFromState(target), args, factorySandboxResolvedSecretEnv(req.ResolvedSecrets), &out)
	result, parseErr := parseFactorySandboxPublishResult(out.Bytes())
	completedAt := deps.now()
	if parseErr != nil {
		if execErr != nil {
			return factoryPublishRunnerResult{}, fmt.Errorf("remote sandbox publish command failed (%w) and output was not valid publish JSON: %v", execErr, parseErr)
		}
		return factoryPublishRunnerResult{}, parseErr
	}
	if !result.OK {
		if strings.TrimSpace(result.Error) != "" {
			return factoryPublishRunnerResult{}, fmt.Errorf("remote sandbox publish failed: %s", strings.TrimSpace(result.Error))
		}
		return factoryPublishRunnerResult{}, fmt.Errorf("remote sandbox publish failed")
	}
	if execErr != nil {
		return factoryPublishRunnerResult{}, fmt.Errorf("remote sandbox publish command failed: %w", execErr)
	}
	attempts := append([]factory.PublishAttempt(nil), priorAttempts...)
	attempts = append(attempts, factory.PublishAttempt{
		Runner:      factory.PublishRunnerSandbox,
		Status:      factory.RunStatusSucceeded,
		StartedAt:   &startedAt,
		CompletedAt: &completedAt,
	})
	return factoryPublishRunnerResult{
		Runner:         factory.PublishRunnerSandbox,
		CredentialMode: factoryPublishCredentialMode(req.ResolvedSecrets),
		Commit:         strings.TrimSpace(result.Commit),
		Push:           result.Push,
		Attempts:       attempts,
	}, nil
}

type factorySandboxPublishResult struct {
	ContractVersion string        `json:"contractVersion"`
	OK              bool          `json:"ok"`
	Push            ci.PushResult `json:"push,omitempty"`
	Commit          string        `json:"commit,omitempty"`
	Error           string        `json:"error,omitempty"`
}

type factoryPublishBranchRequest struct {
	Policy     string
	BranchName string
	BaseBranch string
	Title      string
	Body       string
	JSON       bool
}

type factoryPublishBranchDeps struct {
	runGit               func(context.Context, string, ...string) (string, error)
	pushAndCreatePRInDir func(context.Context, string, ci.PushOptions) (ci.PushResult, error)
}

func runFactoryPublishBranch(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	req := factoryPublishBranchRequest{
		Policy:     factoryPublishBranchPolicyFlag,
		BranchName: factoryPublishBranchBranchFlag,
		BaseBranch: factoryPublishBranchBaseFlag,
		Title:      factoryPublishBranchTitleFlag,
		Body:       factoryPublishBranchBodyFlag,
		JSON:       factoryPublishBranchJSONFlag,
	}
	if cmd != nil {
		out = cmd.OutOrStdout()
		if cmd.Flags().Lookup("policy") != nil {
			value, err := cmd.Flags().GetString("policy")
			if err != nil {
				return err
			}
			req.Policy = value
		}
		if cmd.Flags().Lookup("branch") != nil {
			value, err := cmd.Flags().GetString("branch")
			if err != nil {
				return err
			}
			req.BranchName = value
		}
		if cmd.Flags().Lookup("base") != nil {
			value, err := cmd.Flags().GetString("base")
			if err != nil {
				return err
			}
			req.BaseBranch = value
		}
		if cmd.Flags().Lookup("title") != nil {
			value, err := cmd.Flags().GetString("title")
			if err != nil {
				return err
			}
			req.Title = value
		}
		if cmd.Flags().Lookup("body") != nil {
			value, err := cmd.Flags().GetString("body")
			if err != nil {
				return err
			}
			req.Body = value
		}
		if cmd.Flags().Lookup("json") != nil {
			value, err := cmd.Flags().GetBool("json")
			if err != nil {
				return err
			}
			req.JSON = value
		}
	}
	ctx := context.Background()
	if cmd != nil {
		ctx = cmd.Context()
	}
	return runFactoryPublishBranchWithDeps(ctx, ".", req, out, factoryPublishBranchDeps{
		runGit:               runFactoryGitInDir,
		pushAndCreatePRInDir: ci.PushAndCreatePRInDir,
	})
}

func runFactoryPublishBranchWithDeps(ctx context.Context, dir string, req factoryPublishBranchRequest, out io.Writer, deps factoryPublishBranchDeps) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if out == nil {
		out = io.Discard
	}
	if deps.runGit == nil {
		return fmt.Errorf("factory publish branch git dependency is required")
	}
	render := func(resp factorySandboxPublishResult) error {
		if strings.TrimSpace(resp.ContractVersion) == "" {
			resp.ContractVersion = "factory-publish-branch-v1"
		}
		data, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal factory publish branch: %w", err)
		}
		fmt.Fprintln(out, string(data))
		return nil
	}
	fail := func(err error) error {
		if req.JSON {
			return render(factorySandboxPublishResult{OK: false, Error: err.Error()})
		}
		return err
	}
	result, commit, err := publishFactoryBranchFromWorkspace(ctx, dir, req, deps)
	if err != nil {
		return fail(err)
	}
	if !req.JSON {
		_, err = fmt.Fprintf(out, "Published branch %s with policy %s\n", result.Branch, strings.ToLower(strings.TrimSpace(req.Policy)))
		return err
	}
	return render(factorySandboxPublishResult{
		OK:     true,
		Push:   result,
		Commit: commit,
	})
}

func publishFactoryBranchFromWorkspace(ctx context.Context, dir string, req factoryPublishBranchRequest, deps factoryPublishBranchDeps) (ci.PushResult, string, error) {
	publishPolicy := strings.ToLower(strings.TrimSpace(req.Policy))
	if publishPolicy == "" {
		return ci.PushResult{}, "", fmt.Errorf("--policy is required and must be one of %s", strings.Join([]string{factory.PublishPolicyPush, factory.PublishPolicyPR}, ", "))
	}
	if publishPolicy != factory.PublishPolicyPush && publishPolicy != factory.PublishPolicyPR {
		return ci.PushResult{}, "", fmt.Errorf("--policy must be one of %s", strings.Join([]string{factory.PublishPolicyPush, factory.PublishPolicyPR}, ", "))
	}
	branchName := strings.TrimSpace(req.BranchName)
	if branchName == "" {
		return ci.PushResult{}, "", fmt.Errorf("--branch is required")
	}
	if _, err := deps.runGit(ctx, dir, "check-ref-format", "--branch", branchName); err != nil {
		return ci.PushResult{}, "", fmt.Errorf("invalid branch %q: %w", branchName, err)
	}
	if err := ensureFactoryPublishWorkspaceBranch(ctx, dir, branchName, deps); err != nil {
		return ci.PushResult{}, "", err
	}
	var result ci.PushResult
	switch publishPolicy {
	case factory.PublishPolicyPush:
		if _, err := deps.runGit(ctx, dir, "push", "-u", "origin", branchName); err != nil {
			return ci.PushResult{}, "", fmt.Errorf("factory publish push branch %q: %w", branchName, err)
		}
		result = ci.PushResult{
			ContractVersion: ci.PushContractVersion,
			Branch:          branchName,
			Pushed:          true,
			Summary:         fmt.Sprintf("pushed branch %s", branchName),
		}
	case factory.PublishPolicyPR:
		if deps.pushAndCreatePRInDir == nil {
			return ci.PushResult{}, "", fmt.Errorf("factory publish pr requires push dependency")
		}
		pushResult, err := deps.pushAndCreatePRInDir(ctx, dir, ci.PushOptions{
			BaseRef: strings.TrimSpace(req.BaseBranch),
			Title:   strings.TrimSpace(req.Title),
			Body:    req.Body,
		})
		if err != nil {
			return ci.PushResult{}, "", fmt.Errorf("factory publish pull request for branch %q: %w", branchName, err)
		}
		if strings.TrimSpace(pushResult.Branch) == "" {
			pushResult.Branch = branchName
		}
		result = pushResult
	}
	commit, _ := deps.runGit(ctx, dir, "rev-parse", "HEAD")
	return result, strings.TrimSpace(commit), nil
}

func ensureFactoryPublishWorkspaceBranch(ctx context.Context, dir, branchName string, deps factoryPublishBranchDeps) error {
	current, err := deps.runGit(ctx, dir, "branch", "--show-current")
	if err != nil {
		return fmt.Errorf("resolve current branch before publish: %w", err)
	}
	if strings.TrimSpace(current) == branchName {
		return nil
	}
	if _, err := deps.runGit(ctx, dir, "show-ref", "--verify", "--quiet", "refs/heads/"+branchName); err == nil {
		if _, checkoutErr := deps.runGit(ctx, dir, "checkout", branchName); checkoutErr != nil {
			return fmt.Errorf("checkout branch %q before publish: %w", branchName, checkoutErr)
		}
		return nil
	}
	if _, err := deps.runGit(ctx, dir, "checkout", "-b", branchName); err != nil {
		return fmt.Errorf("create branch %q before publish: %w", branchName, err)
	}
	return nil
}

func factorySandboxRemotePublishArgs(record factory.RunRecord, req factoryRunRequest, publishPolicy, branchName string) ([]string, error) {
	workspaceDir := factorySandboxRemoteWorkspaceDir(record)
	if workspaceDir == "" {
		return nil, errFactorySandboxWorkspaceRequired
	}
	args := []string{
		"factory", "_publish-branch",
		"--policy", publishPolicy,
		"--branch", branchName,
		"--base", strings.TrimSpace(req.BaseBranch),
		"--title", factoryPublishPRTitle(record),
		"--body", factoryPublishPRBody(record),
		"--json",
	}
	publishScript := "set -eu\ncd " + shellQuote(workspaceDir) + "\n" + factorySandboxRemoteHalScript(args) + " 2>/tmp/hal-factory-publish-stderr"
	return []string{"sh", "-lc", publishScript}, nil
}

func parseFactorySandboxPublishResult(data []byte) (*factorySandboxPublishResult, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("parse remote sandbox publish JSON: empty output")
	}
	var result factorySandboxPublishResult
	if err := json.Unmarshal(trimmed, &result); err != nil {
		return nil, fmt.Errorf("parse remote sandbox publish JSON: %w", err)
	}
	return &result, nil
}

func ensureFactorySandboxRecoveryBundleForPublish(ctx context.Context, store factory.Store, dir string, req factoryRunRequest, record factory.RunRecord, deps factoryRunDeps, policy factory.FactoryPolicy) (factory.RunRecord, error) {
	if !req.Sandbox || !factoryPublishPolicyRequiresHostArtifacts(policy) {
		return record, nil
	}
	if updatedRecord, err := store.LoadRun(record.RunID); err != nil {
		return record, fmt.Errorf("reload factory run before sandbox recovery artifact collection: %w", err)
	} else if updatedRecord != nil {
		record = *updatedRecord
	}
	if _, ok := factoryRunRecoveryBundleArtifact(record); ok {
		return record, nil
	}
	if !factoryRunCanCollectSandboxArtifacts(deps) {
		return record, nil
	}
	collectionRecord := record
	collectionRecord.ExecutorMode = factory.ExecutorModeSandbox
	if strings.TrimSpace(collectionRecord.SandboxName) == "" {
		collectionRecord.SandboxName = strings.TrimSpace(req.SandboxName)
	}
	if err := collectAndStoreFactorySandboxArtifacts(ctx, store, dir, req, collectionRecord, deps); err != nil {
		return record, fmt.Errorf("collect sandbox recovery artifacts before publish: %w", err)
	}
	updatedRecord, err := store.LoadRun(record.RunID)
	if err != nil {
		return record, fmt.Errorf("reload factory run after sandbox recovery artifact collection: %w", err)
	}
	if updatedRecord == nil {
		return record, nil
	}
	return *updatedRecord, nil
}

func factoryRunCanCollectSandboxArtifacts(deps factoryRunDeps) bool {
	if deps.sandboxCopier != nil {
		return true
	}
	return deps.loadSandbox != nil &&
		deps.resolveProvider != nil &&
		(deps.runProviderExec != nil || deps.runProviderExecIO != nil)
}

func applyFactorySandboxRecoveryBundle(ctx context.Context, store factory.Store, dir string, record factory.RunRecord, deps factoryRunDeps) (string, string, error) {
	branchName := strings.TrimSpace(record.BranchName)
	if branchName == "" {
		return "", "", fmt.Errorf("apply sandbox recovery bundle: branch name is required")
	}
	if deps.runGit == nil {
		return "", "", fmt.Errorf("apply sandbox recovery bundle: git dependency is required")
	}
	if _, err := deps.runGit(ctx, dir, "check-ref-format", "--branch", branchName); err != nil {
		return "", "", fmt.Errorf("apply sandbox recovery bundle: invalid branch %q: %w", branchName, err)
	}
	artifact, ok := factoryRunRecoveryBundleArtifact(record)
	if !ok {
		return "", "", fmt.Errorf("apply sandbox recovery bundle: recovery bundle artifact is unavailable")
	}
	bundlePath, err := store.ResolveArtifactPath(record.RunID, artifact.StoredPath)
	if err != nil {
		return "", "", fmt.Errorf("apply sandbox recovery bundle: resolve artifact path: %w", err)
	}
	if _, err := deps.runGit(ctx, dir, "fetch", "--no-tags", bundlePath, "HEAD"); err != nil {
		return "", "", fmt.Errorf("apply sandbox recovery bundle: fetch bundle: %w", err)
	}
	exists := factoryRunBranchExists(ctx, dir, branchName, deps)
	if exists {
		if _, err := deps.runGit(ctx, dir, "checkout", branchName); err != nil {
			return "", "", fmt.Errorf("apply sandbox recovery bundle: checkout branch %q: %w", branchName, err)
		}
		if _, err := deps.runGit(ctx, dir, "merge", "--ff-only", "FETCH_HEAD"); err != nil {
			return "", "", fmt.Errorf("apply sandbox recovery bundle: fast-forward branch %q: %w", branchName, err)
		}
		return branchName, artifact.StoredPath, nil
	}
	if _, err := deps.runGit(ctx, dir, "checkout", "-b", branchName, "FETCH_HEAD"); err != nil {
		return "", "", fmt.Errorf("apply sandbox recovery bundle: create branch %q: %w", branchName, err)
	}
	return branchName, artifact.StoredPath, nil
}

func factoryRunBranchExists(ctx context.Context, dir, branchName string, deps factoryRunDeps) bool {
	if deps.runGit == nil {
		return false
	}
	_, err := deps.runGit(ctx, dir, "show-ref", "--verify", "--quiet", "refs/heads/"+branchName)
	return err == nil
}

func factoryRunRecoveryBundleArtifact(record factory.RunRecord) (factory.ArtifactReference, bool) {
	for _, artifact := range record.Artifacts {
		if artifact.Partial || strings.TrimSpace(artifact.StoredPath) == "" {
			continue
		}
		if summaryString(artifact.Summary, "outcomeKind") == "recovery_bundle" {
			return artifact, true
		}
		if artifact.ID == "sandbox-recovery-bundle" || artifact.Name == "sandbox-recovery-bundle" {
			return artifact, true
		}
	}
	return factory.ArtifactReference{}, false
}

func summaryString(summary map[string]any, key string) string {
	if len(summary) == 0 {
		return ""
	}
	switch value := summary[key].(type) {
	case string:
		return strings.TrimSpace(value)
	case fmt.Stringer:
		return strings.TrimSpace(value.String())
	default:
		if value == nil {
			return ""
		}
		return strings.TrimSpace(fmt.Sprint(value))
	}
}

func factoryStringSliceContains(values []string, want string) bool {
	want = strings.TrimSpace(want)
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}

func publishFactoryRunBranch(ctx context.Context, dir string, req factoryRunRequest, record factory.RunRecord, deps factoryRunDeps, publishPolicy, branchName string) (ci.PushResult, error) {
	switch publishPolicy {
	case factory.PublishPolicyPush:
		if deps.runGit == nil {
			return ci.PushResult{}, fmt.Errorf("factory publish push requires git dependency")
		}
		if _, err := deps.runGit(ctx, dir, "push", "-u", "origin", branchName); err != nil {
			return ci.PushResult{}, fmt.Errorf("factory publish push branch %q: %w", branchName, err)
		}
		return ci.PushResult{
			ContractVersion: ci.PushContractVersion,
			Branch:          branchName,
			Pushed:          true,
			Summary:         fmt.Sprintf("pushed branch %s", branchName),
		}, nil
	case factory.PublishPolicyPR:
		if deps.pushAndCreatePRInDir == nil {
			return ci.PushResult{}, fmt.Errorf("factory publish pr requires push dependency")
		}
		result, err := deps.pushAndCreatePRInDir(ctx, dir, ci.PushOptions{
			BaseRef: strings.TrimSpace(req.BaseBranch),
			Title:   factoryPublishPRTitle(record),
			Body:    factoryPublishPRBody(record),
		})
		if err != nil {
			return ci.PushResult{}, fmt.Errorf("factory publish pull request for branch %q: %w", branchName, err)
		}
		return result, nil
	default:
		return ci.PushResult{}, fmt.Errorf("factory publish policy %q is unsupported", publishPolicy)
	}
}

func recordFactoryPublishOutcomeArtifact(store factory.Store, record factory.RunRecord, publishPolicy, recoveredBundle string, result ci.PushResult, redactor factory.RunSecretRedactor, source string, allowUnverified bool, completedAt time.Time, runner, fallbackFrom, credentialMode, commit string, attempts []factory.PublishAttempt) (factory.RunRecord, error) {
	var pr *ci.PullRequest
	if strings.TrimSpace(result.PullRequest.URL) != "" || result.PullRequest.Number != 0 || strings.TrimSpace(result.PullRequest.HeadRef) != "" {
		copied := result.PullRequest
		pr = &copied
	}
	pullRequestURL := ""
	pullRequestID := 0
	if pr != nil {
		pullRequestURL = strings.TrimSpace(pr.URL)
		pullRequestID = pr.Number
	}
	artifact, tempPath, err := materializeFactoryJSONArtifact("publish-outcome", "factory/publish-outcome.json", factoryPublishOutcomeArtifact{
		Policy:          publishPolicy,
		Runner:          runner,
		FallbackFrom:    fallbackFrom,
		CredentialMode:  credentialMode,
		BranchName:      result.Branch,
		Commit:          commit,
		RecoveredBundle: recoveredBundle,
		Pushed:          result.Pushed,
		PullRequest:     pr,
		Attempts:        attempts,
		Summary:         result.Summary,
	}, map[string]any{
		"outcomeKind":    "publish",
		"policy":         publishPolicy,
		"runner":         runner,
		"fallbackFrom":   fallbackFrom,
		"credentialMode": credentialMode,
		"branch":         result.Branch,
		"branchName":     result.Branch,
		"commit":         commit,
		"pushed":         result.Pushed,
		"status":         factory.RunStatusSucceeded,
	})
	if err != nil {
		return record, err
	}
	if pullRequestURL != "" {
		artifact.Summary["pullRequestUrl"] = pullRequestURL
	}
	if recoveredBundle != "" {
		artifact.Summary["recoveredBundle"] = recoveredBundle
	}
	if pullRequestID != 0 {
		artifact.Summary["pullRequestId"] = pullRequestID
	}
	if len(attempts) > 0 {
		artifact.Summary["attempts"] = attempts
	}
	defer func() { _ = os.Remove(tempPath) }()
	if _, err := store.SaveArtifactFileWithRedactor(record.RunID, artifact, tempPath, redactor); err != nil {
		return record, fmt.Errorf("store factory publish outcome artifact: %w", err)
	}
	updatedRecord, err := store.LoadRun(record.RunID)
	if err != nil {
		return record, fmt.Errorf("reload factory run after publish artifact: %w", err)
	}
	if updatedRecord.PostRun == nil {
		updatedRecord.PostRun = &factory.PostRunState{}
	}
	completedAt = completedAt.UTC()
	updatedRecord.PostRun.Publish = &factory.PublishOutcome{
		Status:          factory.RunStatusSucceeded,
		Policy:          strings.TrimSpace(publishPolicy),
		Runner:          strings.TrimSpace(runner),
		BranchName:      strings.TrimSpace(result.Branch),
		Commit:          strings.TrimSpace(commit),
		RecoveredBundle: strings.TrimSpace(recoveredBundle),
		Pushed:          result.Pushed,
		PullRequestURL:  pullRequestURL,
		PullRequestID:   pullRequestID,
		CredentialMode:  strings.TrimSpace(credentialMode),
		FallbackFrom:    strings.TrimSpace(fallbackFrom),
		Attempts:        append([]factory.PublishAttempt(nil), attempts...),
		AllowUnverified: allowUnverified,
		Source:          strings.TrimSpace(source),
		CompletedAt:     &completedAt,
	}
	if err := store.SaveRunWithRedactor(updatedRecord, redactor); err != nil {
		return record, fmt.Errorf("record factory post-run publish metadata: %w", err)
	}
	updatedRecord, err = store.LoadRun(record.RunID)
	if err != nil {
		return record, fmt.Errorf("reload factory run after post-run publish metadata: %w", err)
	}
	return *updatedRecord, nil
}

func factoryPublishPRTitle(record factory.RunRecord) string {
	branchName := strings.TrimSpace(record.BranchName)
	if branchName == "" {
		return ""
	}
	return "hal factory: " + branchName
}

func factoryPublishPRBody(record factory.RunRecord) string {
	parts := []string{"Automated pull request created by `hal factory run`."}
	if runID := strings.TrimSpace(record.RunID); runID != "" {
		parts = append(parts, "", "Factory run: `"+runID+"`")
	}
	if sandboxName := strings.TrimSpace(record.SandboxName); sandboxName != "" {
		parts = append(parts, "Sandbox: `"+sandboxName+"`")
	}
	return strings.Join(parts, "\n")
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

func collectAndStoreFactoryVerificationArtifacts(store factory.Store, dir, runID string, artifacts []verify.ArtifactReference, artifactSourceDir string, redactor factory.RunSecretRedactor) error {
	for _, artifact := range artifacts {
		path := strings.TrimSpace(artifact.Path)
		if path == "" {
			continue
		}
		sourcePath := factoryVerificationArtifactSourcePath(dir, path, artifactSourceDir)
		if explicitSourcePath := strings.TrimSpace(artifact.SourcePath()); explicitSourcePath != "" {
			sourcePath = explicitSourcePath
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
			Path: filepath.ToSlash(filepath.Clean(path)),
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

func factoryVerificationArtifactSourcePath(projectDir, artifactPath, artifactSourceDir string) string {
	if filepath.IsAbs(artifactPath) {
		return artifactPath
	}
	if strings.TrimSpace(artifactSourceDir) == "" {
		return filepath.Join(projectDir, artifactPath)
	}

	displayPrefix := path.Join(template.HalDir, "reports", "verify")
	cleanArtifactPath := path.Clean(filepath.ToSlash(artifactPath))
	if rel := strings.TrimPrefix(cleanArtifactPath, displayPrefix+"/"); rel != cleanArtifactPath && rel != "" {
		return filepath.Join(artifactSourceDir, filepath.FromSlash(rel))
	}

	return filepath.Join(projectDir, artifactPath)
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
	redactor := factory.NewRunSecretRedactor(req.ResolvedSecrets)
	if deps.sandboxCopier != nil {
		if _, err := factory.CollectSandboxArtifactsWithRedactor(ctx, store, record.RunID, deps.sandboxCopier, requests, redactor); err != nil {
			_ = recordFactoryRunArtifactSyncFailedWithRedactor(store, record.RunID, factoryRunDepsNow(deps), err, redactor)
			return fmt.Errorf("collect sandbox factory artifacts: %w", err)
		}
		return nil
	}
	target, provider, err := resolveFactorySandboxArtifactCollectionTarget(dir, record, deps)
	if err != nil {
		return err
	}
	if target == nil || provider == nil {
		return nil
	}
	if err := collectAndStoreFactorySandboxArtifactRequestsWithProviderExec(ctx, store, req, record, deps, target, provider, requests); err != nil {
		return fmt.Errorf("collect sandbox factory artifacts: %w", err)
	}
	return nil
}

func factoryRunDepsNow(deps factoryRunDeps) time.Time {
	if deps.now != nil {
		return deps.now()
	}
	return time.Now()
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
		{
			ID:         "sandbox-recovery",
			Name:       "sandbox-recovery",
			Type:       "directory",
			RemotePath: filepath.ToSlash(filepath.Join(template.HalDir, "recovery")),
			Path:       filepath.ToSlash(filepath.Join(template.HalDir, "recovery")),
			Directory:  true,
			Optional:   true,
			Summary:    factorySandboxArtifactSummary(summary, "outcomeKind", "recovery_directory"),
		},
		{
			ID:         "sandbox-recovery-patch",
			Name:       "sandbox-recovery-patch",
			Type:       "patch",
			RemotePath: filepath.ToSlash(filepath.Join(template.HalDir, "recovery", "git-format-patch.patch")),
			Path:       filepath.ToSlash(filepath.Join("factory", "git-format-patch.patch")),
			Optional:   true,
			Summary:    factorySandboxArtifactSummary(summary, "outcomeKind", "recovery_patch"),
		},
		{
			ID:         "sandbox-recovery-bundle",
			Name:       "sandbox-recovery-bundle",
			Type:       "bundle",
			RemotePath: filepath.ToSlash(filepath.Join(template.HalDir, "recovery", "git-bundle.bundle")),
			Path:       filepath.ToSlash(filepath.Join("factory", "git-bundle.bundle")),
			Optional:   true,
			Summary:    factorySandboxArtifactSummary(summary, "outcomeKind", "recovery_bundle"),
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

func factorySandboxArtifactSummary(base map[string]any, key string, value any) map[string]any {
	out := make(map[string]any, len(base)+1)
	for k, v := range base {
		out[k] = v
	}
	out[key] = value
	return out
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
	resolvedArchivedPath := c.resolvePath(archivedPath)
	if !factoryArtifactFileExists(resolvedArchivedPath) {
		return false
	}
	c.add(factory.ArtifactReference{
		Name:       name,
		Type:       factoryArtifactTypeForPath(path),
		Path:       c.displayPath(path),
		SourcePath: resolvedArchivedPath,
	})
	return true
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
			"error":  sanitizeFactoryArtifactEventError(artifactErr, redactor),
		},
	}, redactor)
}

func recordFactoryRunArtifactSyncFailedWithRedactor(store factory.Store, runID string, now time.Time, artifactErr error, redactor factory.RunSecretRedactor) error {
	return appendFactoryRunTimelineEventWithRedactor(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypeArtifactSync,
		Summary:   "Factory sandbox artifact sync failed",
		Metadata: map[string]any{
			"step":   factory.RunDurationStepArtifactCollect,
			"status": factory.RunStatusFailed,
			"error":  sanitizeFactoryArtifactEventError(artifactErr, redactor),
		},
	}, redactor)
}

func sanitizeFactoryArtifactEventError(err error, redactor factory.RunSecretRedactor) string {
	if err == nil {
		return "artifact collection failed"
	}
	errorMessage := sanitizeFactoryLogText(redactFactoryString(err.Error(), redactor))
	if strings.TrimSpace(errorMessage) == "" {
		return "artifact collection failed"
	}
	return errorMessage
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

func recordFactoryRunPublishStarted(store factory.Store, runID string, now time.Time, publishPolicy string, runner string) error {
	return appendFactoryRunTimelineEvent(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypeStepStarted,
		Summary:   "Factory publish started",
		Metadata: map[string]any{
			"step":   factory.RunDurationStepFinalization,
			"status": factory.RunStatusRunning,
			"policy": strings.TrimSpace(publishPolicy),
			"runner": strings.TrimSpace(runner),
		},
	})
}

func recordFactoryRunPublishSucceeded(store factory.Store, runID string, now time.Time, publishPolicy string, runner string, result ci.PushResult) error {
	metadata := map[string]any{
		"step":   factory.RunDurationStepFinalization,
		"status": factory.RunStatusSucceeded,
		"policy": strings.TrimSpace(publishPolicy),
		"runner": strings.TrimSpace(runner),
		"branch": strings.TrimSpace(result.Branch),
		"pushed": result.Pushed,
	}
	if prURL := strings.TrimSpace(result.PullRequest.URL); prURL != "" {
		metadata["pullRequestUrl"] = prURL
	}
	return appendFactoryRunTimelineEvent(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypeStepEnded,
		Summary:   "Factory publish completed",
		Metadata:  metadata,
	})
}

func recordFactoryRunPublishFailedWithRedactor(store factory.Store, runID string, now time.Time, publishErr error, redactor factory.RunSecretRedactor) error {
	return appendFactoryRunTimelineEventWithRedactor(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypeStepEnded,
		Summary:   "Factory publish failed",
		Metadata: map[string]any{
			"step":   factory.RunDurationStepFinalization,
			"status": factory.RunStatusFailed,
			"error":  sanitizeFactoryArtifactEventError(publishErr, redactor),
		},
	}, redactor)
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
	return recordFactoryRunVerificationAdvisoryFailedWithRedactor(store, runID, now, verificationErr, factory.RunSecretRedactor{})
}

func recordFactoryRunVerificationAdvisoryFailedWithRedactor(store factory.Store, runID string, now time.Time, verificationErr error, redactor factory.RunSecretRedactor) error {
	return appendFactoryRunTimelineEventWithRedactor(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypeStepEnded,
		Summary:   "Verification failed (advisory)",
		Metadata: map[string]any{
			"step":     factory.RunDurationStepVerification,
			"status":   factory.RunStatusFailed,
			"advisory": true,
			"blocking": false,
			"error":    verificationErr.Error(),
		},
	}, redactor)
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
	event.Message = redactFactoryString(event.Message, redactor)
	event.Summary = redactFactoryString(event.Summary, redactor)
	event.Metadata = redactFactoryTimelineMetadata(event.Metadata, redactor)
	event.NetworkPolicyDecisionLogs = sandbox.SanitizeSandboxNetworkPolicyDecisionLogRecords(event.NetworkPolicyDecisionLogs)
	return event
}

func redactFactoryTimelineMetadata(metadata map[string]any, redactor factory.RunSecretRedactor) map[string]any {
	if len(metadata) == 0 {
		return nil
	}
	safe := make(map[string]any, len(metadata))
	for key, value := range metadata {
		safeKey := redactFactoryString(key, redactor)
		if factoryTimelineMetadataCredentialDeliveryKey(key) || factoryTimelineMetadataCredentialDeliveryKey(safeKey) {
			status := sanitizeFactoryTimelineCredentialDeliveryMetadataValue(value)
			if status != nil {
				safe[safeKey] = *status
			}
			continue
		}
		if omitFactoryTimelineMetadataEntry(key, safeKey, reflect.ValueOf(value)) {
			continue
		}
		safe[safeKey] = redactFactoryTimelineValue(value, redactor)
	}
	if len(safe) == 0 {
		return nil
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
		redacted := redactFactoryString(value.String(), redactor)
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
			if omitFactoryTimelineMetadataReflectEntry(key, redactedKey, iter.Value()) {
				changed = true
				continue
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
	case reflect.Struct:
		out := reflect.New(value.Type()).Elem()
		out.Set(value)
		changed := false
		for i := 0; i < value.NumField(); i++ {
			field := value.Field(i)
			outField := out.Field(i)
			if !outField.CanSet() {
				continue
			}
			redacted, ok := redactFactoryTimelineReflectValue(field, redactor)
			if !ok {
				continue
			}
			if redacted.Type().AssignableTo(outField.Type()) {
				outField.Set(redacted)
				changed = true
				continue
			}
			if redacted.Type().ConvertibleTo(outField.Type()) {
				outField.Set(redacted.Convert(outField.Type()))
				changed = true
			}
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

func omitFactoryTimelineMetadataReflectEntry(rawKey, safeKey, value reflect.Value) bool {
	if factoryTimelineMetadataKeyOmitted(reflectString(rawKey)) || factoryTimelineMetadataKeyOmitted(reflectString(safeKey)) {
		return true
	}
	return factoryTimelineMetadataValueOmitted(value)
}

func omitFactoryTimelineMetadataEntry(rawKey, safeKey string, value reflect.Value) bool {
	if factoryTimelineMetadataKeyOmitted(rawKey) || factoryTimelineMetadataKeyOmitted(safeKey) {
		return true
	}
	return factoryTimelineMetadataValueOmitted(value)
}

func reflectString(value reflect.Value) string {
	if !value.IsValid() || value.Kind() != reflect.String {
		return ""
	}
	return value.String()
}

func factoryTimelineMetadataKeyOmitted(key string) bool {
	normalized := normalizeFactoryTimelineMetadataKey(key)
	if strings.HasPrefix(normalized, "credentialproxy") {
		return true
	}
	switch normalized {
	case "credentialdelivery",
		"credentialdeliveryclaim",
		"credentialdeliverystatus",
		"credentialproxydelivery",
		"credentialproxydeliveryclaim",
		"credentialproxydeliverystatus",
		"proxyenforcement",
		"networkenforcement",
		"sshagentforwarding",
		"tmpfswrites",
		"runtimesupport":
		return true
	default:
		return false
	}
}

func factoryTimelineMetadataCredentialDeliveryKey(key string) bool {
	return normalizeFactoryTimelineMetadataKey(key) == "credentialdelivery"
}

func normalizeFactoryTimelineMetadataKey(key string) string {
	return strings.ToLower(strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.TrimSpace(key)))
}

func sanitizeFactoryTimelineCredentialDeliveryMetadataValue(value any) *sandbox.SandboxCredentialDeliveryStatusMetadata {
	var status sandbox.SandboxCredentialDeliveryStatusMetadata
	switch typed := value.(type) {
	case sandbox.SandboxCredentialDeliveryStatusMetadata:
		status = typed
	case *sandbox.SandboxCredentialDeliveryStatusMetadata:
		if typed == nil {
			return nil
		}
		status = *typed
	default:
		data, err := json.Marshal(value)
		if err != nil {
			return nil
		}
		if err := json.Unmarshal(data, &status); err != nil {
			return nil
		}
	}
	return sandboxCommandJSONCredentialDeliveryStatus(&status)
}

func factoryTimelineMetadataValueOmitted(value reflect.Value) bool {
	if !value.IsValid() {
		return false
	}
	for {
		switch value.Kind() {
		case reflect.Interface, reflect.Pointer:
			if value.IsNil() {
				return false
			}
			value = value.Elem()
		case reflect.Slice, reflect.Array:
			if factoryTimelineMetadataTypeOmitted(value.Type().Elem()) {
				return true
			}
			for i := 0; i < value.Len(); i++ {
				if factoryTimelineMetadataValueOmitted(value.Index(i)) {
					return true
				}
			}
			return false
		default:
			return factoryTimelineMetadataTypeOmitted(value.Type())
		}
	}
}

func factoryTimelineMetadataTypeOmitted(typ reflect.Type) bool {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	return typ.PkgPath() == "github.com/jywlabs/hal/internal/sandbox" &&
		strings.HasPrefix(typ.Name(), "SandboxCredentialProxy")
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
		Sequence:                  nextFactoryRunEventSequence(events),
		RunID:                     runID,
		EventType:                 event.EventType,
		Timestamp:                 timestamp.UTC(),
		Message:                   event.Message,
		Summary:                   event.Summary,
		Metadata:                  event.Metadata,
		NetworkPolicyDecisionLogs: event.NetworkPolicyDecisionLogs,
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
	autoReq.WorkDir = strings.TrimSpace(req.WorkDir)
	autoReq.Engine = strings.TrimSpace(req.Engine)
	autoReq.AttemptPolicy = req.AttemptPolicy
	autoReq.MaxCommandRetries = req.MaxCommandRetries
	autoReq.CIPolicy = strings.TrimSpace(req.CIPolicy)
	autoReq.RuntimeStatePolicy = strings.TrimSpace(req.RuntimeStatePolicy)
	autoReq.SkipCI = req.SkipCI
	now := req.Now
	if now == nil {
		now = time.Now
	}
	startedAt := now()
	if err := recordFactoryRunLogChunk(req.Store, req.RunID, factory.LogStreamSummary, factory.LogSourceLocalFactory, "", "Starting local hal auto pipeline", &startedAt); err != nil {
		return err
	}
	attempts := factoryCommandAttemptCount(autoReq.MaxCommandRetries)
	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		runReq := autoReq
		if attempt > 1 {
			runReq = factoryRunResumeAutoRequest(autoReq)
			retryAt := now()
			_ = recordFactoryRunLogChunk(req.Store, req.RunID, factory.LogStreamSummary, factory.LogSourceLocalFactory, "", fmt.Sprintf("Retrying local hal auto pipeline (%d/%d)", attempt, attempts), &retryAt)
		}
		err = deps.runAuto(ctx, runReq)
		if err == nil {
			break
		}
		if attempt >= attempts || !factoryRunCanRetryLocalAuto(ctx, runReq.WorkDir, err) {
			failedAt := now()
			_ = recordFactoryRunLogChunk(req.Store, req.RunID, factory.LogStreamStderr, factory.LogSourceLocalFactory, redactor.RedactString(err.Error()), "Local hal auto pipeline failed", &failedAt)
			return err
		}
		failedAt := now()
		_ = recordFactoryRunLogChunk(req.Store, req.RunID, factory.LogStreamStderr, factory.LogSourceLocalFactory, redactor.RedactString(err.Error()), fmt.Sprintf("Local hal auto pipeline attempt %d failed; retrying with resume", attempt), &failedAt)
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
		CIPolicy:   strings.TrimSpace(req.CIPolicy),
	}
	if markdownPath := strings.TrimSpace(req.MarkdownPath); markdownPath != "" {
		autoReq.Args = []string{markdownPath}
	}
	return autoReq
}

func factoryRunResumeAutoRequest(req factoryRunAutoRequest) factoryRunAutoRequest {
	resumeReq := req
	resumeReq.Resume = true
	resumeReq.Args = nil
	resumeReq.ReportPath = ""
	resumeReq.BaseBranch = ""
	return resumeReq
}

func factoryCommandAttemptCount(maxRetries int) int {
	if maxRetries < 0 {
		return 1
	}
	return maxRetries + 1
}

func factoryRunCanRetryLocalAuto(ctx context.Context, workDir string, err error) bool {
	if !factoryCommandErrorIsRetryable(ctx, err) {
		return false
	}
	if strings.TrimSpace(workDir) == "" {
		workDir = "."
	}
	statePath := filepath.Join(workDir, template.HalDir, template.AutoStateFile)
	info, statErr := os.Stat(statePath)
	return statErr == nil && !info.IsDir()
}

func factoryCommandErrorIsRetryable(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var limitErr *compound.PolicyLimitError
	if errors.As(err, &limitErr) {
		return false
	}
	errText := strings.ToLower(err.Error())
	for _, marker := range []string{
		"no saved state to resume from",
		"post-convert branch invariant failed",
		"current branch",
		"unexpected dirty files",
		"working tree is dirty",
		"reached attempt limit",
		"ci still failing",
		"must be greater than or equal to 0",
		"must be one of",
	} {
		if strings.Contains(errText, marker) {
			return false
		}
	}
	return true
}

func runAutoForFactoryRun(ctx context.Context, req factoryRunAutoRequest) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = contextWithAutoFactoryAttemptPolicy(ctx, req.AttemptPolicy)
	ctx = contextWithAutoFactoryCIPolicy(ctx, req.CIPolicy)
	ctx = contextWithAutoFactoryRuntimeStatePolicy(ctx, req.RuntimeStatePolicy)

	cmd, err := factoryRunAutoCommand(ctx, req)
	if err != nil {
		return err
	}
	args := req.Args
	if req.Resume {
		args = nil
	}
	return runAutoWithDir(cmd, args, req.WorkDir)
}

func factoryRunAutoCommand(ctx context.Context, req factoryRunAutoRequest) (*cobra.Command, error) {
	cmd := &cobra.Command{Use: "auto"}
	cmd.SetContext(ctx)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.Flags().Bool("dry-run", false, "")
	cmd.Flags().Bool("resume", req.Resume, "")
	if req.Resume {
		if err := cmd.Flags().Set("resume", "true"); err != nil {
			return nil, err
		}
	}
	cmd.Flags().Bool("no-ci", req.SkipCI, "")
	cmd.Flags().Bool("skip-pr", false, "")
	cmd.Flags().Bool("no-review", false, "")
	cmd.Flags().String("mode", "", "")
	cmd.Flags().Int("review-streak", 0, "")
	cmd.Flags().Int("review-max", 0, "")
	reportPath := strings.TrimSpace(req.ReportPath)
	if req.Resume {
		reportPath = ""
	}
	cmd.Flags().String("report", reportPath, "")
	engineName := factoryRunAutoEngine(req.Engine)
	cmd.Flags().String("engine", engineName, "")
	if strings.TrimSpace(req.Engine) != "" {
		if err := cmd.Flags().Set("engine", engineName); err != nil {
			return nil, err
		}
	}
	baseBranch := strings.TrimSpace(req.BaseBranch)
	if req.Resume {
		baseBranch = ""
	}
	cmd.Flags().String("base", baseBranch, "")
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

func loadFactoryCommandConfig(projectDir string) (*projectconfig.Config, error) {
	cfg, err := projectconfig.Load(projectDir)
	if err != nil {
		return nil, fmt.Errorf("load project config: %w", err)
	}
	return cfg, nil
}

func applyFactoryRunConfigDefaults(req factoryRunRequest, secretEnv []string, changes factoryRunConfigFlagChanges, cfg *projectconfig.Config) (factoryRunRequest, []string, factoryRunConfigFlagChanges) {
	if cfg == nil {
		return req, secretEnv, changes
	}

	defaults := cfg.Factory
	if !changes.Base && defaults.Base.Set {
		req.BaseBranch = defaults.Base.Value
	}
	if !changes.Sandbox && defaults.Executor.Set && defaults.Executor.Value == factory.ExecutorModeSandbox {
		req.Sandbox = true
	}
	if !changes.PublishFrom && defaults.PublishFrom.Set {
		req.PublishFrom = defaults.PublishFrom.Value
		changes.PublishFrom = true
	}
	if !changes.SecretEnv && defaults.SecretEnv.Set {
		secretEnv = append([]string(nil), defaults.SecretEnv.Value...)
	}
	if req.Sandbox {
		if !changes.SandboxName && defaults.SandboxName.Set {
			req.SandboxName = defaults.SandboxName.Value
			changes.SandboxName = true
		}
		if !changes.SandboxHost && defaults.SandboxHost.Set {
			req.SandboxHostID = defaults.SandboxHost.Value
			changes.SandboxHost = true
		}
		if !changes.SandboxRuntime && defaults.SandboxRuntime.Set {
			req.SandboxRuntime = defaults.SandboxRuntime.Value
			changes.SandboxRuntime = true
		}
	}

	return req, secretEnv, changes
}

func applyFactoryPublishConfigDefaults(req factoryPublishRequest, changes factoryPublishConfigFlagChanges, cfg *projectconfig.Config, policy *factory.FactoryPolicy) factoryPublishRequest {
	if cfg != nil {
		defaults := cfg.Factory
		if !changes.PublishFrom && defaults.PublishFrom.Set {
			req.PublishFrom = defaults.PublishFrom.Value
		}
		if !changes.SecretEnv && defaults.SecretEnv.Set {
			req.SecretEnv = append([]string(nil), defaults.SecretEnv.Value...)
		}
	}
	if !changes.Policy && policy != nil {
		switch strings.TrimSpace(policy.PublishPolicy) {
		case factory.PublishPolicyPush, factory.PublishPolicyPR:
			req.Policy = policy.PublishPolicy
		}
	}
	return req
}

func factoryRunRequestFromCommand(cmd *cobra.Command, args []string) (factoryRunRequest, error) {
	reportPath := factoryRunReportFlag
	baseBranch := factoryRunBaseFlag
	secretEnv := append([]string(nil), factoryRunSecretEnvFlags...)
	baseChanged := strings.TrimSpace(factoryRunBaseFlag) != ""
	secretEnvChanged := len(factoryRunSecretEnvFlags) > 0
	ciPolicy := factoryRunCIPolicyFlag
	ciPolicyChanged := false
	noCI := factoryRunNoCIFlag
	noCIChanged := false
	publishPolicy := factoryRunPublishFlag
	publishPolicyChanged := false
	publishFrom := factoryRunPublishFromFlag
	publishFromChanged := false
	jsonMode := factoryRunJSONFlag
	sandboxMode := factoryRunSandboxFlag
	sandboxChanged := factoryRunSandboxFlag
	sandboxName := factoryRunSandboxNameFlag
	sandboxNameChanged := false
	sandboxHost := factoryRunSandboxHostFlag
	sandboxHostChanged := strings.TrimSpace(factoryRunSandboxHostFlag) != ""
	sandboxRuntime := factoryRunSandboxRuntimeFlag
	sandboxRuntimeChanged := strings.TrimSpace(factoryRunSandboxRuntimeFlag) != ""

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
			baseChanged = cmd.Flags().Changed("base")
		}
		if cmd.Flags().Lookup("secret-env") != nil {
			value, err := cmd.Flags().GetStringArray("secret-env")
			if err != nil {
				return factoryRunRequest{}, err
			}
			secretEnv = value
			secretEnvChanged = cmd.Flags().Changed("secret-env")
		}
		if cmd.Flags().Lookup("ci-policy") != nil {
			value, err := cmd.Flags().GetString("ci-policy")
			if err != nil {
				return factoryRunRequest{}, err
			}
			ciPolicy = value
			ciPolicyChanged = cmd.Flags().Changed("ci-policy")
		}
		if cmd.Flags().Lookup("no-ci") != nil {
			value, err := cmd.Flags().GetBool("no-ci")
			if err != nil {
				return factoryRunRequest{}, err
			}
			noCI = value
			noCIChanged = cmd.Flags().Changed("no-ci")
		}
		if cmd.Flags().Lookup("publish") != nil {
			value, err := cmd.Flags().GetString("publish")
			if err != nil {
				return factoryRunRequest{}, err
			}
			publishPolicy = value
			publishPolicyChanged = cmd.Flags().Changed("publish")
		}
		if cmd.Flags().Lookup("publish-from") != nil {
			value, err := cmd.Flags().GetString("publish-from")
			if err != nil {
				return factoryRunRequest{}, err
			}
			publishFrom = value
			publishFromChanged = cmd.Flags().Changed("publish-from")
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
			sandboxChanged = cmd.Flags().Changed("sandbox")
		}
		if cmd.Flags().Lookup("sandbox-name") != nil {
			value, err := cmd.Flags().GetString("sandbox-name")
			if err != nil {
				return factoryRunRequest{}, err
			}
			sandboxName = value
			sandboxNameChanged = cmd.Flags().Changed("sandbox-name")
		}
		if cmd.Flags().Lookup(sandboxHostFlagName) != nil {
			value, err := cmd.Flags().GetString(sandboxHostFlagName)
			if err != nil {
				return factoryRunRequest{}, err
			}
			sandboxHost = value
			sandboxHostChanged = cmd.Flags().Changed(sandboxHostFlagName)
		}
		if cmd.Flags().Lookup(sandboxRuntimeFlagName) != nil {
			value, err := cmd.Flags().GetString(sandboxRuntimeFlagName)
			if err != nil {
				return factoryRunRequest{}, err
			}
			sandboxRuntime = value
			sandboxRuntimeChanged = cmd.Flags().Changed(sandboxRuntimeFlagName)
		}
	}

	cfg, err := loadFactoryCommandConfig(".")
	if err != nil {
		return factoryRunRequest{}, err
	}
	defaultedReq, secretEnv, defaultChanges := applyFactoryRunConfigDefaults(factoryRunRequest{
		BaseBranch:     baseBranch,
		PublishFrom:    publishFrom,
		Sandbox:        sandboxMode,
		SandboxName:    sandboxName,
		SandboxHostID:  sandboxHost,
		SandboxRuntime: sandboxRuntime,
	}, secretEnv, factoryRunConfigFlagChanges{
		Base:           baseChanged,
		Sandbox:        sandboxChanged,
		SandboxName:    sandboxNameChanged,
		SandboxHost:    sandboxHostChanged,
		SandboxRuntime: sandboxRuntimeChanged,
		PublishFrom:    publishFromChanged,
		SecretEnv:      secretEnvChanged,
	}, cfg)
	baseBranch = defaultedReq.BaseBranch
	publishFrom = defaultedReq.PublishFrom
	sandboxMode = defaultedReq.Sandbox
	sandboxName = defaultedReq.SandboxName
	sandboxNameChanged = defaultChanges.SandboxName
	sandboxHost = defaultedReq.SandboxHostID
	sandboxHostChanged = defaultChanges.SandboxHost
	sandboxRuntime = defaultedReq.SandboxRuntime
	sandboxRuntimeChanged = defaultChanges.SandboxRuntime
	publishFromChanged = defaultChanges.PublishFrom

	req, err := parseFactoryRunRequestWithTargetAndPublishFrom(args, reportPath, baseBranch, jsonMode, sandboxMode, sandboxTargetFlagValues{
		HostID:         sandboxHost,
		HostChanged:    sandboxHostChanged,
		RuntimeDriver:  sandboxRuntime,
		RuntimeChanged: sandboxRuntimeChanged,
	}, sandboxName, sandboxNameChanged, ciPolicy, ciPolicyChanged, noCI, noCIChanged, publishPolicy, publishPolicyChanged, publishFrom, publishFromChanged)
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
	return parseFactoryRunRequestWithTarget(args, reportPath, baseBranch, jsonMode, sandboxMode, sandboxTargetFlagValues{}, "", false, "", false, false, false, "", false)
}

func parseFactoryRunRequestWithTarget(args []string, reportPath, baseBranch string, jsonMode bool, sandboxMode bool, targetFlags sandboxTargetFlagValues, sandboxName string, sandboxNameChanged bool, ciPolicy string, ciPolicyChanged bool, noCI bool, noCIChanged bool, publishPolicy string, publishPolicyChanged bool) (factoryRunRequest, error) {
	return parseFactoryRunRequestWithTargetAndPublishFrom(args, reportPath, baseBranch, jsonMode, sandboxMode, targetFlags, sandboxName, sandboxNameChanged, ciPolicy, ciPolicyChanged, noCI, noCIChanged, publishPolicy, publishPolicyChanged, "", false)
}

func parseFactoryRunRequestWithTargetAndPublishFrom(args []string, reportPath, baseBranch string, jsonMode bool, sandboxMode bool, targetFlags sandboxTargetFlagValues, sandboxName string, sandboxNameChanged bool, ciPolicy string, ciPolicyChanged bool, noCI bool, noCIChanged bool, publishPolicy string, publishPolicyChanged bool, publishFrom string, publishFromChanged bool) (factoryRunRequest, error) {
	if len(args) > 1 {
		return factoryRunRequest{}, fmt.Errorf("accepts at most 1 arg(s), received %d", len(args))
	}
	if len(args) == 1 && strings.TrimSpace(reportPath) != "" {
		return factoryRunRequest{}, fmt.Errorf("--report cannot be used with a positional PRD markdown path")
	}
	if sandboxMode && strings.TrimSpace(baseBranch) == "" {
		return factoryRunRequest{}, fmt.Errorf("--base is required when --sandbox is set")
	}
	sandboxName = strings.TrimSpace(sandboxName)
	if !sandboxNameChanged {
		sandboxName = ""
	}
	if sandboxNameChanged {
		if sandboxName == "" {
			return factoryRunRequest{}, fmt.Errorf("--sandbox-name must not be empty")
		}
		if !sandboxMode {
			return factoryRunRequest{}, fmt.Errorf("--sandbox-name requires --sandbox")
		}
	}
	ciPolicy = strings.ToLower(strings.TrimSpace(ciPolicy))
	if !ciPolicyChanged {
		ciPolicy = ""
	}
	if noCIChanged && noCI {
		if ciPolicyChanged && ciPolicy != "" && ciPolicy != factory.CIPolicyDisabled {
			return factoryRunRequest{}, fmt.Errorf("--no-ci cannot be combined with --ci-policy %s", ciPolicy)
		}
		ciPolicy = factory.CIPolicyDisabled
		ciPolicyChanged = true
	}
	if ciPolicyChanged {
		if ciPolicy == "" {
			return factoryRunRequest{}, fmt.Errorf("--ci-policy must not be empty")
		}
		if !factoryStringSliceContains(factory.SupportedCIPolicies(), ciPolicy) {
			return factoryRunRequest{}, fmt.Errorf("--ci-policy must be one of %s", strings.Join(factory.SupportedCIPolicies(), ", "))
		}
	}
	publishPolicy = strings.ToLower(strings.TrimSpace(publishPolicy))
	if !publishPolicyChanged {
		publishPolicy = ""
	}
	if publishPolicyChanged {
		if publishPolicy == "" {
			return factoryRunRequest{}, fmt.Errorf("--publish must not be empty")
		}
		if !factoryStringSliceContains(factory.SupportedPublishPolicies(), publishPolicy) {
			return factoryRunRequest{}, fmt.Errorf("--publish must be one of %s", strings.Join(factory.SupportedPublishPolicies(), ", "))
		}
	}
	normalizedPublishFrom, err := normalizeFactoryPublishFrom(publishFrom, publishFromChanged)
	if err != nil {
		return factoryRunRequest{}, err
	}
	if normalizedPublishFrom == factory.PublishRunnerSandbox && !sandboxMode {
		return factoryRunRequest{}, fmt.Errorf("--publish-from sandbox requires --sandbox")
	}
	parsedTargetFlags, err := parseSandboxTargetFlagValues(targetFlags)
	if err != nil {
		return factoryRunRequest{}, err
	}
	if err := validateSandboxTargetFlagsRequireSandbox(sandboxMode, targetFlags); err != nil {
		return factoryRunRequest{}, err
	}

	req := factoryRunRequest{
		ReportPath:     reportPath,
		BaseBranch:     baseBranch,
		CIPolicy:       ciPolicy,
		PublishPolicy:  publishPolicy,
		PublishFrom:    normalizedPublishFrom,
		Sandbox:        sandboxMode,
		SandboxName:    sandboxName,
		SandboxHostID:  parsedTargetFlags.HostID,
		SandboxRuntime: parsedTargetFlags.RuntimeDriver,
		JSON:           jsonMode,
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

func normalizeFactoryPublishFrom(value string, changed bool) (string, error) {
	if !changed && strings.TrimSpace(value) == "" {
		return "", nil
	}
	normalized, err := factory.ValidatePublishRunner(value)
	if err != nil {
		return "", fmt.Errorf("--publish-from must be one of %s", strings.Join(factory.SupportedPublishRunners(), ", "))
	}
	return normalized, nil
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

func runFactoryRecover(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	jsonMode := factoryRecoverJSONFlag

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

	ctx := context.Background()
	if cmd != nil {
		ctx = cmd.Context()
	}
	return runFactoryRecoverWithDeps(ctx, out, args[0], jsonMode, defaultFactoryRecoverDeps)
}

func runFactoryPublish(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	if cmd != nil {
		out = cmd.OutOrStdout()
	}

	req, err := factoryPublishRequestFromCommand(cmd)
	if err != nil {
		return err
	}

	ctx := context.Background()
	if cmd != nil {
		ctx = cmd.Context()
	}
	return runFactoryPublishWithDeps(ctx, out, args[0], req, defaultFactoryPublishDeps)
}

func factoryPublishRequestFromCommand(cmd *cobra.Command) (factoryPublishRequest, error) {
	policy := factoryPublishPolicyFlag
	policyChanged := strings.TrimSpace(factoryPublishPolicyFlag) != ""
	publishFrom := factoryPublishFromFlag
	publishFromChanged := false
	secretEnv := append([]string(nil), factoryPublishSecretEnvFlags...)
	secretEnvChanged := len(factoryPublishSecretEnvFlags) > 0
	allowUnverified := factoryPublishAllowUnverifiedFlag
	jsonMode := factoryPublishJSONFlag

	if cmd != nil {
		if cmd.Flags().Lookup("policy") != nil {
			value, err := cmd.Flags().GetString("policy")
			if err != nil {
				return factoryPublishRequest{}, err
			}
			policy = value
			policyChanged = cmd.Flags().Changed("policy")
		}
		if cmd.Flags().Lookup("publish-from") != nil {
			value, err := cmd.Flags().GetString("publish-from")
			if err != nil {
				return factoryPublishRequest{}, err
			}
			publishFrom = value
			publishFromChanged = cmd.Flags().Changed("publish-from")
		}
		if cmd.Flags().Lookup("secret-env") != nil {
			value, err := cmd.Flags().GetStringArray("secret-env")
			if err != nil {
				return factoryPublishRequest{}, err
			}
			secretEnv = value
			secretEnvChanged = cmd.Flags().Changed("secret-env")
		}
		if cmd.Flags().Lookup("allow-unverified") != nil {
			value, err := cmd.Flags().GetBool("allow-unverified")
			if err != nil {
				return factoryPublishRequest{}, err
			}
			allowUnverified = value
		}
		if cmd.Flags().Lookup("json") != nil {
			value, err := cmd.Flags().GetBool("json")
			if err != nil {
				return factoryPublishRequest{}, err
			}
			jsonMode = value
		}
	}

	cfg, err := loadFactoryCommandConfig(".")
	if err != nil {
		return factoryPublishRequest{}, err
	}
	var policyConfig *factory.FactoryPolicy
	if !policyChanged {
		policyConfig, err = factory.LoadPolicyConfig(".")
		if err != nil {
			return factoryPublishRequest{}, fmt.Errorf("load factory policy: %w", err)
		}
	}
	req := factoryPublishRequest{
		Policy:          policy,
		PublishFrom:     publishFrom,
		SecretEnv:       secretEnv,
		AllowUnverified: allowUnverified,
		JSON:            jsonMode,
	}
	req = applyFactoryPublishConfigDefaults(req, factoryPublishConfigFlagChanges{
		Policy:      policyChanged,
		PublishFrom: publishFromChanged,
		SecretEnv:   secretEnvChanged,
	}, cfg, policyConfig)
	return req, nil
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

func runFactoryRecoverWithDeps(ctx context.Context, out io.Writer, runID string, jsonMode bool, deps factoryRecoverDeps) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if out == nil {
		out = io.Discard
	}
	if deps.defaultStore == nil {
		return fmt.Errorf("factory store dependency is required")
	}
	if deps.workingDir == nil {
		return fmt.Errorf("factory recover working directory dependency is required")
	}
	if deps.now == nil {
		deps.now = time.Now
	}
	if deps.runGit == nil {
		return fmt.Errorf("factory recover git dependency is required")
	}
	fail := func(status string, err error) error {
		if !jsonMode {
			return err
		}
		return renderFactoryRecoverJSON(out, FactoryRecoverResponse{
			ContractVersion: FactoryRecoverContractVersion,
			OK:              false,
			RunID:           runID,
			Status:          status,
			Error:           err.Error(),
		})
	}

	store, err := deps.defaultStore()
	if err != nil {
		return fail("", fmt.Errorf("open factory store: %w", err))
	}
	record, err := store.LoadRun(runID)
	if errors.Is(err, fs.ErrNotExist) {
		return fail("", fmt.Errorf("factory run %q not found", runID))
	}
	if err != nil {
		return fail("", fmt.Errorf("load factory run %q: %w", runID, err))
	}
	dir, err := deps.workingDir()
	if err != nil {
		return fail(record.Status, fmt.Errorf("resolve working directory: %w", err))
	}

	branchName, bundlePath, err := applyFactorySandboxRecoveryBundle(ctx, store, dir, *record, factoryRunDeps{
		now:    deps.now,
		runGit: deps.runGit,
	})
	if err != nil {
		return fail(record.Status, err)
	}
	resp := FactoryRecoverResponse{
		ContractVersion: FactoryRecoverContractVersion,
		OK:              true,
		RunID:           record.RunID,
		Status:          record.Status,
		BranchName:      branchName,
		RecoveredBundle: bundlePath,
	}
	if jsonMode {
		return renderFactoryRecoverJSON(out, resp)
	}
	_, err = fmt.Fprintf(out, "Recovered run %s onto branch %s\n", resp.RunID, resp.BranchName)
	return err
}

type factoryPublishRequest struct {
	Policy          string
	PublishFrom     string
	SecretEnv       []string
	Secrets         []factory.RunSecretInput
	ResolvedSecrets []factory.ResolvedRunSecret
	AllowUnverified bool
	JSON            bool
}

func runFactoryPublishWithDeps(ctx context.Context, out io.Writer, runID string, req factoryPublishRequest, deps factoryPublishDeps) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if out == nil {
		out = io.Discard
	}
	if deps.defaultStore == nil {
		return fmt.Errorf("factory store dependency is required")
	}
	if deps.workingDir == nil {
		return fmt.Errorf("factory publish working directory dependency is required")
	}
	if deps.now == nil {
		deps.now = time.Now
	}
	if deps.lookupEnv == nil {
		deps.lookupEnv = os.LookupEnv
	}
	fail := func(status string, err error) error {
		if !req.JSON {
			return err
		}
		return renderFactoryPublishJSON(out, FactoryPublishResponse{
			ContractVersion: FactoryPublishContractVersion,
			OK:              false,
			RunID:           runID,
			Status:          status,
			Policy:          strings.ToLower(strings.TrimSpace(req.Policy)),
			PublishFrom:     strings.ToLower(strings.TrimSpace(req.PublishFrom)),
			AllowUnverified: req.AllowUnverified,
			Error:           err.Error(),
		})
	}

	publishPolicy := strings.ToLower(strings.TrimSpace(req.Policy))
	if publishPolicy == "" {
		return fail("", fmt.Errorf("--policy is required and must be one of %s", strings.Join([]string{factory.PublishPolicyPush, factory.PublishPolicyPR}, ", ")))
	}
	if publishPolicy != factory.PublishPolicyPush && publishPolicy != factory.PublishPolicyPR {
		return fail("", fmt.Errorf("--policy must be one of %s", strings.Join([]string{factory.PublishPolicyPush, factory.PublishPolicyPR}, ", ")))
	}
	publishFrom, err := normalizeFactoryPublishFrom(req.PublishFrom, strings.TrimSpace(req.PublishFrom) != "")
	if err != nil {
		return fail("", err)
	}
	if publishFrom == "" {
		publishFrom = factory.PublishRunnerHost
	}
	req.PublishFrom = publishFrom
	if (publishFrom == factory.PublishRunnerHost || publishFrom == factory.PublishRunnerAuto) && deps.runGit == nil {
		return fail("", fmt.Errorf("factory publish git dependency is required"))
	}
	secrets, err := parseFactoryRunSecretEnvFlags(req.SecretEnv)
	if err != nil {
		return fail("", err)
	}
	req.Secrets = secrets
	resolvedSecrets, _, secretErr := factory.ResolveRunSecrets(req.Secrets, deps.lookupEnv)
	req.ResolvedSecrets = resolvedSecrets
	redactor := factory.NewRunSecretRedactor(req.ResolvedSecrets)
	if secretErr != nil {
		return fail("", redactFactoryRunError(secretErr, redactor))
	}

	store, err := deps.defaultStore()
	if err != nil {
		return fail("", fmt.Errorf("open factory store: %w", err))
	}
	record, err := store.LoadRun(runID)
	if errors.Is(err, fs.ErrNotExist) {
		return fail("", fmt.Errorf("factory run %q not found", runID))
	}
	if err != nil {
		return fail("", fmt.Errorf("load factory run %q: %w", runID, err))
	}
	if !factoryRunIsVerifiedForManualPublish(*record) && !req.AllowUnverified {
		return fail(record.Status, fmt.Errorf("factory run %q is %s and may be unverified; rerun with --allow-unverified to publish it", record.RunID, record.Status))
	}
	dir, err := deps.workingDir()
	if err != nil {
		return fail(record.Status, fmt.Errorf("resolve working directory: %w", err))
	}

	updatedRecord, err := publishFactoryRunAfterVerifiedSuccess(ctx, store, dir, factoryRunRequest{
		Sandbox:         record.ExecutorMode == factory.ExecutorModeSandbox,
		SandboxName:     record.SandboxName,
		BaseBranch:      record.BaseBranch,
		PublishFrom:     req.PublishFrom,
		ResolvedSecrets: req.ResolvedSecrets,
	}, *record, factoryRunDeps{
		now:                    deps.now,
		loadSandbox:            deps.loadSandbox,
		resolveProvider:        deps.resolveProvider,
		runProviderExec:        deps.runProviderExec,
		runProviderExecIO:      deps.runProviderExecIO,
		runProviderExecWithEnv: deps.runProviderExecWithEnv,
		sandboxRequests:        deps.sandboxRequests,
		runGit:                 deps.runGit,
		pushAndCreatePRInDir:   deps.pushAndCreatePRInDir,
	}, factory.FactoryPolicy{PublishPolicy: publishPolicy}, redactor, "manual", req.AllowUnverified)
	if err != nil {
		return fail(record.Status, redactFactoryRunError(err, redactor))
	}
	postRun := factory.DerivePostRunState(updatedRecord)
	resp := FactoryPublishResponse{
		ContractVersion: FactoryPublishContractVersion,
		OK:              true,
		RunID:           updatedRecord.RunID,
		Status:          updatedRecord.Status,
		DisplayStatus:   factory.DeriveDisplayStatus(updatedRecord),
		PipelineStatus:  updatedRecord.Status,
		PublishStatus:   factoryPublishStatus(postRun),
		Policy:          publishPolicy,
		PublishFrom:     req.PublishFrom,
		Runner:          factoryPublishRunner(postRun),
		AllowUnverified: req.AllowUnverified,
		BranchName:      strings.TrimSpace(updatedRecord.BranchName),
		PullRequestURL:  factoryPublishPullRequestURL(postRun),
		Artifacts:       newFactoryArtifactSummaries(updatedRecord.Artifacts),
	}
	if req.JSON {
		return renderFactoryPublishJSON(out, resp)
	}
	_, err = fmt.Fprintf(out, "Published run %s with policy %s on branch %s\n", resp.RunID, resp.Policy, resp.BranchName)
	return err
}

func factoryRunIsVerifiedForManualPublish(record factory.RunRecord) bool {
	return record.Status == factory.RunStatusSucceeded || record.Status == factory.RunStatusSucceededWithWarnings
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
	postRun := factory.DerivePostRunState(record)
	return FactoryStatusRun{
		RunID:                 record.RunID,
		Status:                record.Status,
		DisplayStatus:         factory.DeriveDisplayStatus(record),
		PipelineStatus:        record.Status,
		PublishStatus:         factoryPublishStatus(postRun),
		ExecutorMode:          record.ExecutorMode,
		Engine:                record.Engine,
		Source:                record.Source,
		RepoPath:              record.RepoPath,
		RepoRemote:            record.RepoRemote,
		BranchName:            record.BranchName,
		BaseBranch:            record.BaseBranch,
		Policy:                factoryPolicySnapshotPointer(record.Policy),
		PolicyDecisions:       factoryPolicyDecisionsFromEvents(events),
		SandboxName:           record.SandboxName,
		Sandbox:               record.Sandbox,
		SecurityReadinessGate: factory.SecurityReadinessGateDecision(record),
		CurrentStep:           record.CurrentStep,
		CreatedAt:             record.CreatedAt,
		UpdatedAt:             record.UpdatedAt,
		FinishedAt:            record.FinishedAt,
		Secrets:               record.Secrets,
		Artifacts:             newFactoryArtifactSummaries(record.Artifacts),
		Verification:          record.Verification,
		Telemetry:             factory.DeriveRunTelemetry(record, events),
		Failure:               normalizedFactoryFailureSummary(record.Failure),
		Handoff:               handoff,
		PostRun:               postRun,
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
		PolicyMode:  sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode(stringFromFactoryMetadata(metadata, "policyMode")),
		Code:        sandbox.SandboxSecurityCapabilityReadinessGateCode(stringFromFactoryMetadata(metadata, "code")),
		Counts:      sandboxSecurityReadinessGateCountsFromFactoryMetadata(metadata["counts"]),
	}
}

func sandboxSecurityReadinessGateCountsFromFactoryMetadata(value any) *sandbox.SandboxSecurityCapabilityReadinessGateCounts {
	switch counts := value.(type) {
	case nil:
		return nil
	case *sandbox.SandboxSecurityCapabilityReadinessGateCounts:
		if counts == nil {
			return nil
		}
		clone := sandboxSecurityReadinessGateCountsClone(*counts)
		return &clone
	case sandbox.SandboxSecurityCapabilityReadinessGateCounts:
		clone := sandboxSecurityReadinessGateCountsClone(counts)
		return &clone
	case map[string]any:
		return sandboxSecurityReadinessGateCountsFromMap(counts)
	case map[string]int:
		return sandboxSecurityReadinessGateCountsFromIntMap(counts)
	default:
		return nil
	}
}

func sandboxSecurityReadinessGateCountsFromMap(values map[string]any) *sandbox.SandboxSecurityCapabilityReadinessGateCounts {
	if len(values) == 0 {
		return nil
	}
	counts := sandbox.SandboxSecurityCapabilityReadinessGateCounts{
		Total:            intFromFactoryMetadata(values["total"]),
		Ready:            intFromFactoryMetadata(values["ready"]),
		Advisory:         intFromFactoryMetadata(values["advisory"]),
		Blocked:          intFromFactoryMetadata(values["blocked"]),
		Missing:          intFromFactoryMetadata(values["missing"]),
		MetadataOnly:     intFromFactoryMetadata(values["metadataOnly"]),
		Unsupported:      intFromFactoryMetadata(values["unsupported"]),
		StrictBlocking:   intFromFactoryMetadata(values["strictBlocking"]),
		ReasonCodeCounts: sandboxSecurityReadinessGateReasonCodeCountsFromFactoryMetadata(values["reasonCodeCounts"]),
	}
	if sandboxSecurityReadinessGateCountsEmpty(counts) {
		return nil
	}
	return &counts
}

func sandboxSecurityReadinessGateCountsFromIntMap(values map[string]int) *sandbox.SandboxSecurityCapabilityReadinessGateCounts {
	if len(values) == 0 {
		return nil
	}
	counts := sandbox.SandboxSecurityCapabilityReadinessGateCounts{
		Total:          values["total"],
		Ready:          values["ready"],
		Advisory:       values["advisory"],
		Blocked:        values["blocked"],
		Missing:        values["missing"],
		MetadataOnly:   values["metadataOnly"],
		Unsupported:    values["unsupported"],
		StrictBlocking: values["strictBlocking"],
	}
	if sandboxSecurityReadinessGateCountsEmpty(counts) {
		return nil
	}
	return &counts
}

func sandboxSecurityReadinessGateCountsClone(counts sandbox.SandboxSecurityCapabilityReadinessGateCounts) sandbox.SandboxSecurityCapabilityReadinessGateCounts {
	clone := counts
	if len(counts.ReasonCodeCounts) > 0 {
		clone.ReasonCodeCounts = make(map[sandbox.SandboxSecurityCapabilityReasonCode]int, len(counts.ReasonCodeCounts))
		for reason, count := range counts.ReasonCodeCounts {
			if safeReason, ok := sandboxSecurityReadinessGateReasonCodeFromString(string(reason)); ok && count > 0 {
				clone.ReasonCodeCounts[safeReason] = count
			}
		}
		if len(clone.ReasonCodeCounts) == 0 {
			clone.ReasonCodeCounts = nil
		}
	}
	return clone
}

func sandboxSecurityReadinessGateCountsEmpty(counts sandbox.SandboxSecurityCapabilityReadinessGateCounts) bool {
	return counts.Total == 0 &&
		counts.Ready == 0 &&
		counts.Advisory == 0 &&
		counts.Blocked == 0 &&
		counts.Missing == 0 &&
		counts.MetadataOnly == 0 &&
		counts.Unsupported == 0 &&
		counts.StrictBlocking == 0 &&
		len(counts.ReasonCodeCounts) == 0
}

func sandboxSecurityReadinessGateReasonCodeCountsFromFactoryMetadata(value any) map[sandbox.SandboxSecurityCapabilityReasonCode]int {
	switch counts := value.(type) {
	case map[string]any:
		return sandboxSecurityReadinessGateReasonCodeCountsFromAnyMap(counts)
	case map[string]int:
		return sandboxSecurityReadinessGateReasonCodeCountsFromIntMap(counts)
	case map[sandbox.SandboxSecurityCapabilityReasonCode]int:
		return sandboxSecurityReadinessGateCountsClone(sandbox.SandboxSecurityCapabilityReadinessGateCounts{ReasonCodeCounts: counts}).ReasonCodeCounts
	default:
		return nil
	}
}

func sandboxSecurityReadinessGateReasonCodeCountsFromAnyMap(values map[string]any) map[sandbox.SandboxSecurityCapabilityReasonCode]int {
	if len(values) == 0 {
		return nil
	}
	counts := make(map[sandbox.SandboxSecurityCapabilityReasonCode]int, len(values))
	for rawReason, rawCount := range values {
		reason, ok := sandboxSecurityReadinessGateReasonCodeFromString(rawReason)
		if !ok {
			continue
		}
		count := intFromFactoryMetadata(rawCount)
		if count <= 0 {
			continue
		}
		counts[reason] = count
	}
	if len(counts) == 0 {
		return nil
	}
	return counts
}

func sandboxSecurityReadinessGateReasonCodeCountsFromIntMap(values map[string]int) map[sandbox.SandboxSecurityCapabilityReasonCode]int {
	if len(values) == 0 {
		return nil
	}
	counts := make(map[sandbox.SandboxSecurityCapabilityReasonCode]int, len(values))
	for rawReason, count := range values {
		reason, ok := sandboxSecurityReadinessGateReasonCodeFromString(rawReason)
		if !ok || count <= 0 {
			continue
		}
		counts[reason] = count
	}
	if len(counts) == 0 {
		return nil
	}
	return counts
}

func sandboxSecurityReadinessGateReasonCodeFromString(value string) (sandbox.SandboxSecurityCapabilityReasonCode, bool) {
	reason := sandbox.SandboxSecurityCapabilityReasonCode(strings.ToLower(strings.TrimSpace(value)))
	switch reason {
	case sandbox.SandboxSecurityCapabilityReasonMetadataOnly,
		sandbox.SandboxSecurityCapabilityReasonCapabilityMissing,
		sandbox.SandboxSecurityCapabilityReasonModeUnsupported,
		sandbox.SandboxSecurityCapabilityReasonCapabilityBlocked,
		sandbox.SandboxSecurityCapabilityReasonCapabilityConfirmed,
		sandbox.SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
		sandbox.SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
		sandbox.SandboxSecurityCapabilityReasonReadinessMissing,
		sandbox.SandboxSecurityCapabilityReasonMicroVMReadinessMissing,
		sandbox.SandboxSecurityCapabilityReasonMicroVMSupportMissing,
		sandbox.SandboxSecurityCapabilityReasonWorkspaceIsolationMissing,
		sandbox.SandboxSecurityCapabilityReasonWorkspaceDirectHostWorktree,
		sandbox.SandboxSecurityCapabilityReasonNetworkEnforcementMissing,
		sandbox.SandboxSecurityCapabilityReasonNetworkEnforcementPlannedOnly,
		sandbox.SandboxSecurityCapabilityReasonNetworkEnforcementBestEffort,
		sandbox.SandboxSecurityCapabilityReasonNetworkEnforcementPartial,
		sandbox.SandboxSecurityCapabilityReasonNetworkEnforcementUnsupported,
		sandbox.SandboxSecurityCapabilityReasonNetworkEnforcementFailed,
		sandbox.SandboxSecurityCapabilityReasonCredentialActivationMissing,
		sandbox.SandboxSecurityCapabilityReasonTemplateLockDigestMissing,
		sandbox.SandboxSecurityCapabilityReasonSelectedTemplateEvidenceMissing,
		sandbox.SandboxSecurityCapabilityReasonSelectedTemplateTrustAdvisoryOnly,
		sandbox.SandboxSecurityCapabilityReasonSelectedTemplateTrustRejected,
		sandbox.SandboxSecurityCapabilityReasonSelectedTemplateTrustUnavailable,
		sandbox.SandboxSecurityCapabilityReasonSelectedTemplateProvenanceUnresolved,
		sandbox.SandboxSecurityCapabilityReasonSelectedTemplateProvenanceMismatch,
		sandbox.SandboxSecurityCapabilityReasonMicroVMReadinessConfirmed,
		sandbox.SandboxSecurityCapabilityReasonWorkspaceIsolationConfirmed,
		sandbox.SandboxSecurityCapabilityReasonNetworkEnforcementConfirmed,
		sandbox.SandboxSecurityCapabilityReasonCredentialActivationConfirmed,
		sandbox.SandboxSecurityCapabilityReasonTemplateLockDigestConfirmed,
		sandbox.SandboxSecurityCapabilityReasonSelectedTemplateTrustConfirmed,
		sandbox.SandboxSecurityCapabilityReasonUnknown:
		return reason, true
	default:
		return "", false
	}
}

func intFromFactoryMetadata(value any) int {
	switch number := value.(type) {
	case int:
		return number
	case int64:
		return int(number)
	case float64:
		return int(number)
	case float32:
		return int(number)
	case json.Number:
		parsed, err := number.Int64()
		if err != nil {
			return 0
		}
		return int(parsed)
	default:
		return 0
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

func renderFactoryRecoverJSON(out io.Writer, resp FactoryRecoverResponse) error {
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal factory recover: %w", err)
	}
	fmt.Fprintln(out, string(data))
	return nil
}

func renderFactoryPublishJSON(out io.Writer, resp FactoryPublishResponse) error {
	if resp.Artifacts == nil {
		resp.Artifacts = []FactoryArtifactSummary{}
	}
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal factory publish: %w", err)
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
	gate := factory.SecurityReadinessGateDecision(*record)
	if jsonMode {
		return renderFactoryRunJSONWithSecurityReadinessGate(out, resp, gate)
	}
	return renderFactoryRunSummaryWithSecurityReadinessGate(out, resp, gate)
}

func summarizeFactoryRun(record factory.RunRecord) FactoryRunSummary {
	postRun := factory.DerivePostRunState(record)
	return FactoryRunSummary{
		RunID:                 record.RunID,
		Status:                record.Status,
		DisplayStatus:         factory.DeriveDisplayStatus(record),
		PipelineStatus:        record.Status,
		PublishStatus:         factoryPublishStatus(postRun),
		Source:                record.Source,
		RepoPath:              record.RepoPath,
		RepoRemote:            record.RepoRemote,
		BranchName:            record.BranchName,
		BaseBranch:            record.BaseBranch,
		SandboxName:           record.SandboxName,
		SecurityReadinessGate: factory.SecurityReadinessGateDecision(record),
		CurrentStep:           record.CurrentStep,
		CreatedAt:             record.CreatedAt,
		UpdatedAt:             record.UpdatedAt,
		FinishedAt:            record.FinishedAt,
		ArtifactCount:         len(record.Artifacts),
		Telemetry:             factory.DeriveRunTelemetry(record, nil),
		Failure:               normalizedFactoryFailureSummary(record.Failure),
		PostRun:               postRun,
	}
}

func factoryPublishStatus(postRun *factory.PostRunState) string {
	if postRun == nil || postRun.Publish == nil {
		return ""
	}
	return strings.TrimSpace(postRun.Publish.Status)
}

func factoryPublishRunner(postRun *factory.PostRunState) string {
	if postRun == nil || postRun.Publish == nil {
		return ""
	}
	return strings.TrimSpace(postRun.Publish.Runner)
}

func factoryPublishCredentialMode(secrets []factory.ResolvedRunSecret) string {
	for _, secret := range secrets {
		if strings.TrimSpace(secret.Source) == factory.RunSecretSourceEnv && strings.TrimSpace(secret.Value) != "" {
			return factory.SecretBrokerDeliveryModeEnv
		}
	}
	return ""
}

func factoryPublishCommitForDir(ctx context.Context, dir string, deps factoryRunDeps) string {
	if deps.runGit == nil {
		return ""
	}
	commit, err := deps.runGit(ctx, dir, "rev-parse", "HEAD")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(commit)
}

func factoryPublishPullRequestURL(postRun *factory.PostRunState) string {
	if postRun == nil || postRun.Publish == nil {
		return ""
	}
	return strings.TrimSpace(postRun.Publish.PullRequestURL)
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
		if len(event.NetworkPolicyDecisionLogs) > 0 {
			normalized[i].NetworkPolicyDecisionLogs = sandbox.SanitizeSandboxNetworkPolicyDecisionLogRecords(event.NetworkPolicyDecisionLogs)
		}
		normalized[i].Metadata = redactFactoryTimelineMetadata(event.Metadata, factory.RunSecretRedactor{})
		if event.EventType != factory.EventTypeFailureClassification || event.Metadata == nil {
			continue
		}
		category, ok := normalized[i].Metadata["category"].(string)
		if !ok {
			continue
		}
		metadata := make(map[string]any, len(normalized[i].Metadata))
		for key, value := range normalized[i].Metadata {
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
			factoryHumanDisplayStatus(record),
			record.BranchName,
			record.CurrentStep,
			formatFactoryListTime(record.UpdatedAt),
		)
	}
	_ = w.Flush()
}

func renderFactoryStatusTable(out io.Writer, record factory.RunRecord, events []factory.EventRecord, handoff *factory.HandoffSummary) {
	telemetry := factory.DeriveRunTelemetry(record, events)
	postRun := factory.DerivePostRunState(record)
	fmt.Fprintf(out, "Run ID: %s\n", record.RunID)
	fmt.Fprintf(out, "Status: %s\n", record.Status)
	if displayStatus := factory.DeriveDisplayStatus(record); displayStatus != "" && displayStatus != record.Status {
		fmt.Fprintf(out, "Display status: %s\n", displayStatus)
	}
	fmt.Fprintf(out, "Branch: %s\n", record.BranchName)
	fmt.Fprintf(out, "Step: %s\n", record.CurrentStep)
	fmt.Fprintf(out, "Updated: %s\n", formatFactoryListTime(record.UpdatedAt))
	renderFactoryStatusPostRun(out, postRun)
	if readiness := factorySecurityReadinessGateHuman(factory.SecurityReadinessGateDecision(record)); readiness != "" {
		fmt.Fprintf(out, "%s\n", readiness)
	}
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

func factoryHumanDisplayStatus(record factory.RunRecord) string {
	displayStatus := factory.DeriveDisplayStatus(record)
	if displayStatus == "" || displayStatus == record.Status {
		return record.Status
	}
	if displayStatus == "failed_published" {
		return "failed · published"
	}
	return displayStatus
}

func renderFactoryStatusPostRun(out io.Writer, postRun *factory.PostRunState) {
	if postRun == nil || postRun.Publish == nil {
		return
	}
	publish := postRun.Publish
	status := strings.TrimSpace(publish.Status)
	if status == "" {
		status = "unknown"
	}
	policy := strings.TrimSpace(publish.Policy)
	if policy == "" {
		policy = "publish"
	}
	branch := strings.TrimSpace(publish.BranchName)
	if branch != "" {
		fmt.Fprintf(out, "Post-run publish: %s via %s on %s\n", status, policy, branch)
	} else {
		fmt.Fprintf(out, "Post-run publish: %s via %s\n", status, policy)
	}
	if publish.PullRequestURL != "" {
		fmt.Fprintf(out, "PR: %s\n", publish.PullRequestURL)
	}
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
	return sanitizeCredentialedRemoteReferences(value)
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
			if host := strings.TrimSpace(parsed.Hostname()); host != "" {
				if net.ParseIP(host) != nil || factoryArtifactEndpointHostNeedsRedaction(host) {
					return true
				}
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
		field = strings.Trim(field, "\"'<>[](){}.,;")
		if net.ParseIP(strings.Trim(field, "[]")) != nil || factoryArtifactFieldHasSecretPrefix(field) {
			return true
		}
	}
	return false
}

func factoryArtifactEndpointHostNeedsRedaction(host string) bool {
	host = strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	for _, suffix := range []string{
		".internal",
		".internal.invalid",
		".invalid",
		".local",
		".test",
	} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func factoryArtifactFieldHasSecretPrefix(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	for _, prefix := range []string{
		"ghp_",
		"github_pat_",
		"gho_",
		"ghu_",
		"ghs_",
		"ghr_",
		"glpat",
		"sk-",
		"xoxb-",
		"xoxp-",
	} {
		if strings.HasPrefix(lower, prefix) {
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

func runFactoryGitInDir(ctx context.Context, dir string, args ...string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	gitArgs := append([]string(nil), args...)
	if strings.TrimSpace(dir) != "" {
		gitArgs = append([]string{"-C", dir}, gitArgs...)
	}
	cmd := exec.CommandContext(ctx, "git", gitArgs...)
	output, err := cmd.CombinedOutput()
	trimmed := strings.TrimSpace(string(output))
	if err != nil {
		if trimmed == "" {
			return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
		}
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, trimmed)
	}
	return trimmed, nil
}

func sanitizeFactoryRunRecordCredentialedRemote(record factory.RunRecord) factory.RunRecord {
	record.RepoRemote = sanitizeCredentialedRemote(record.RepoRemote)
	record.Failure = sanitizeFactoryRunFailureCredentialedRemote(record.Failure)
	return record
}

func redactFactoryRunRecordForStorage(record factory.RunRecord, redactor factory.RunSecretRedactor) factory.RunRecord {
	return sanitizeFactoryRunRecordCredentialedRemote(redactor.RedactRunRecord(record))
}

func sanitizeFactoryRunFailureCredentialedRemote(failure *factory.FailureSummary) *factory.FailureSummary {
	if failure == nil {
		return nil
	}
	safe := *failure
	safe.Step = sanitizeCredentialedRemoteReferences(safe.Step)
	safe.Category = sanitizeCredentialedRemoteReferences(safe.Category)
	safe.Message = sanitizeCredentialedRemoteReferences(safe.Message)
	safe.SuggestedCommand = sanitizeCredentialedRemoteReferences(safe.SuggestedCommand)
	return &safe
}

func redactFactoryString(value string, redactor factory.RunSecretRedactor) string {
	return sanitizeCredentialedRemoteReferences(redactor.RedactString(value))
}

func sanitizeCredentialedRemote(remote string) string {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return remote
	}
	if sanitized, ok := sanitizeCredentialedRemoteSCPStyle(remote); ok {
		remote = sanitized
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
	if strings.Contains(value, `\/`) {
		value = strings.ReplaceAll(value, `\/`, `/`)
	}
	if !strings.Contains(value, "://") && !strings.Contains(value, "@") {
		return value
	}
	var out strings.Builder
	for i := 0; i < len(value); {
		if factoryCredentialedRemoteReferenceSeparator(value[i]) {
			out.WriteByte(value[i])
			i++
			continue
		}
		end := i
		for end < len(value) && !factoryCredentialedRemoteReferenceSeparator(value[end]) {
			end++
		}
		segment := value[i:end]
		if strings.Contains(segment, "://") || strings.Contains(segment, "@") {
			out.WriteString(sanitizeCredentialedRemote(segment))
		} else {
			out.WriteString(segment)
		}
		i = end
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

func sanitizeCredentialedRemoteSCPStyle(value string) (string, bool) {
	if strings.Contains(value, "://") || !strings.Contains(value, "@") {
		return value, false
	}
	var out strings.Builder
	changed := false
	last := 0
	for i := 0; i < len(value); {
		atOffset := strings.Index(value[i:], "@")
		if atOffset < 0 {
			break
		}
		at := i + atOffset
		start := at
		for start > 0 && factorySCPStyleUserinfoChar(value[start-1]) {
			start--
		}
		userinfo := value[start:at]
		hostStart := at + 1
		hostEnd := hostStart
		for hostEnd < len(value) && factorySCPStyleHostChar(value[hostEnd]) {
			hostEnd++
		}
		if userinfo == "" || hostEnd == hostStart || hostEnd >= len(value) || value[hostEnd] != ':' {
			i = at + 1
			continue
		}
		pathStart := hostEnd + 1
		if pathStart >= len(value) || factorySCPStylePathTerminator(value[pathStart]) {
			i = at + 1
			continue
		}
		if !factorySCPStyleUserinfoLooksCredentialed(userinfo, value[hostStart:hostEnd]) {
			i = at + 1
			continue
		}
		out.WriteString(value[last:start])
		out.WriteString(factory.RunSecretRedactionPlaceholder)
		last = at
		changed = true
		i = at + 1
	}
	if !changed {
		return value, false
	}
	out.WriteString(value[last:])
	return out.String(), true
}

func factorySCPStyleUserinfoChar(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') ||
		(ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9') ||
		ch == '.' || ch == '_' || ch == '-' || ch == '+' || ch == ':' || ch == '%'
}

func factorySCPStyleHostChar(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') ||
		(ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9') ||
		ch == '.' || ch == '-' || ch == '_' || ch == '[' || ch == ']'
}

func factorySCPStylePathTerminator(ch byte) bool {
	switch ch {
	case ' ', '\t', '\n', '\r', '"', '\'', '<', '>', '`':
		return true
	default:
		return false
	}
}

func factorySCPStyleUserinfoLooksCredentialed(userinfo, host string) bool {
	normalized := strings.ToLower(strings.TrimSpace(userinfo))
	if normalized == "" || normalized == "git" {
		return false
	}
	if strings.Contains(normalized, ":") || isCredentialedRemoteParameterKey(normalized) {
		return true
	}
	for _, marker := range []string{"ghp_", "github_pat_", "glpat", "oauth", "x-access-token", "x-token-auth"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	switch strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]") {
	case "github.com", "ssh.github.com", "gitlab.com", "bitbucket.org":
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
	case "token", "access_token", "access_key", "api_key", "apikey", "auth", "auth_token", "credential", "credentials", "password", "passwd", "secret", "client_secret", "private_key", "private_token":
		return true
	default:
		return strings.Contains(normalized, "token") ||
			strings.Contains(normalized, "secret") ||
			strings.Contains(normalized, "password") ||
			strings.Contains(normalized, "credential") ||
			strings.Contains(normalized, "private_key") ||
			strings.Contains(normalized, "access_key")
	}
}
