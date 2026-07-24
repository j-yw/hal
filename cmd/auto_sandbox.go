package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	pathpkg "path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

type autoSandboxOptions struct {
	DryRun                bool
	DryRunChanged         bool
	Resume                bool
	ResumeChanged         bool
	NoCI                  bool
	NoCIChanged           bool
	SkipPR                bool
	SkipPRChanged         bool
	NoReview              bool
	NoReviewChanged       bool
	Mode                  string
	ModeChanged           bool
	ReviewStreak          int
	ReviewStreakChanged   bool
	ReviewMax             int
	ReviewMaxChanged      bool
	Report                string
	ReportChanged         bool
	Engine                string
	EngineChanged         bool
	Base                  string
	BaseChanged           bool
	JSON                  bool
	JSONChanged           bool
	SandboxName           string
	SandboxNameChanged    bool
	SandboxHostID         string
	SandboxHostChanged    bool
	SandboxRuntime        string
	SandboxRuntimeChanged bool
	SandboxSyncOut        bool
	SandboxSyncOutChanged bool
	SandboxApply          bool
	SandboxApplyChanged   bool
}

type autoSandboxRequest struct {
	ExecutionID                  string
	JSON                         bool
	Args                         []string
	SandboxName                  string
	SandboxHostID                string
	SandboxRuntime               string
	ProjectDir                   string
	WorkDir                      string
	RepoRemote                   string
	BaseBranch                   string
	RunBranch                    string
	RemoteCommand                []string
	Env                          map[string]string
	Flags                        autoSandboxOptions
	SyncOut                      sandboxSyncOutOptions
	Workspace                    *sandbox.SandboxWorkspace
	WorkspacePlan                *sandboxworkspace.Plan
	Security                     sandbox.SecurityEvaluationRequest
	SecurityReadinessGateMode    sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode
	SecurityReadinessGate        *sandbox.SandboxSecurityCapabilityReadinessGateDecision
	NetworkProxySession          *sandbox.SandboxNetworkProxySessionMetadata
	NetworkPolicyDecisionLogs    []sandbox.SandboxNetworkPolicyDecisionLogRecord
	CredentialDeliveryActivation credentialDeliveryActivationResult
	WorkerJob                    *sandboxexecution.WorkerJobReference
	Finalization                 *sandboxexecution.FinalizationMetadata
}

type autoSandboxExecutionResult struct {
	Result          *sandboxexec.Result
	RuntimeDriver   sandboxruntime.Driver
	RemoteStarted   bool
	PreparedCommand []string
	StdoutSummary   string
	StderrSummary   string
}

type autoSandboxExecutionHooks struct {
	OnTargetReady     func(*sandbox.SandboxState) error
	OnWorkerJobUpdate func(*sandboxexecution.WorkerJobReference) error
}

type autoSandboxDeps struct {
	defaultStore           func() (sandboxexecution.Store, error)
	durableLeaseStore      bool
	newExecutionID         func(time.Time) string
	now                    func() time.Time
	planWorkspace          func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error)
	loadSandbox            func(string) (*sandbox.SandboxState, error)
	listSandboxes          func() ([]*sandbox.SandboxState, error)
	listHosts              func() ([]*sandbox.SandboxHost, error)
	listLeases             func() ([]*sandbox.SandboxLease, error)
	resolveDefault         func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error)
	provision              func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error)
	acquireLease           func(sandbox.SandboxLeaseAcquireRequest, time.Duration) (*sandbox.SandboxLease, error)
	releaseLease           func(string) (*sandbox.SandboxLease, error)
	resolveProvider        func(string) (sandbox.Provider, error)
	resolveRuntimeDriver   func(sandboxruntime.Target) (sandboxruntime.Driver, error)
	resolveWorkerRuntime   func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error)
	persistSandboxState    func(*sandbox.SandboxState) error
	runProviderExecWithEnv func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, map[string]string, io.Writer) error
	runProviderScript      func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error
	engineAuthFiles        func() []factorySandboxAuthFile
	bootstrap              func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error)
	materializeWorkspace   func(context.Context, sandboxexec.PrepareContext, sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error)
	prepareCommandContext  func(context.Context, sandboxexec.PrepareContext, string, string, io.Writer) (sandboxworkspace.MaterializationOperation, error)
	applySyncOut           sandboxSyncOutApplier
	workerJobWait          func(context.Context) error
	execute                func(context.Context, autoSandboxRequest, io.Writer, io.Writer, autoSandboxExecutionHooks) (autoSandboxExecutionResult, error)

	customRuntimeResolver bool
}

var defaultAutoSandboxDeps = autoSandboxDeps{
	defaultStore:        sandboxexecution.DefaultStore,
	durableLeaseStore:   true,
	newExecutionID:      defaultAutoSandboxExecutionID,
	now:                 time.Now,
	planWorkspace:       defaultRunSandboxWorkspacePlan,
	loadSandbox:         sandbox.LoadActiveInstance,
	listSandboxes:       sandbox.ListActiveInstances,
	listHosts:           sandbox.ListHosts,
	resolveDefault:      sandbox.ResolveDefault,
	provision:           provisionFactorySandbox,
	persistSandboxState: sandbox.ForceWriteInstance,
	resolveProvider: func(providerName string) (sandbox.Provider, error) {
		return resolveStoredProviderWithFallback(".", providerName)
	},
	runProviderExecWithEnv: runFactorySandboxProviderExecWithEnv,
	runProviderScript:      runFactorySandboxProviderScript,
	engineAuthFiles:        factorySandboxEngineAuthFiles,
	bootstrap:              factory.BootstrapWorkspace,
}

func parseAutoSandboxRequest(args []string, opts autoSandboxOptions) (autoSandboxRequest, error) {
	if len(args) > 1 {
		return autoSandboxRequest{}, fmt.Errorf("accepts at most 1 arg(s), received %d", len(args))
	}
	if opts.SandboxNameChanged && strings.TrimSpace(opts.SandboxName) == "" {
		return autoSandboxRequest{}, fmt.Errorf("--sandbox-name must not be empty")
	}
	if opts.EngineChanged && strings.TrimSpace(opts.Engine) == "" {
		return autoSandboxRequest{}, fmt.Errorf("--engine must not be empty")
	}
	if opts.NoReview && (opts.ReviewStreakChanged || opts.ReviewMaxChanged) {
		return autoSandboxRequest{}, fmt.Errorf("--no-review cannot be combined with --review-streak or --review-max")
	}
	if opts.ReviewStreakChanged && opts.ReviewStreak <= 0 {
		return autoSandboxRequest{}, fmt.Errorf("--review-streak must be greater than 0")
	}
	if opts.ReviewMaxChanged && opts.ReviewMax <= 0 {
		return autoSandboxRequest{}, fmt.Errorf("--review-max must be greater than 0")
	}
	if opts.Resume {
		return autoSandboxRequest{}, fmt.Errorf("hal auto --sandbox --resume is not supported yet; resume state path rewriting is required first")
	}
	targetFlags, err := parseSandboxTargetFlagValues(sandboxTargetFlagValues{
		HostID:         opts.SandboxHostID,
		HostChanged:    opts.SandboxHostChanged,
		RuntimeDriver:  opts.SandboxRuntime,
		RuntimeChanged: opts.SandboxRuntimeChanged,
	})
	if err != nil {
		return autoSandboxRequest{}, err
	}
	syncOut := parseSandboxSyncOutFlagValues(sandboxSyncOutFlagValues{
		SyncOut:        opts.SandboxSyncOut,
		SyncOutChanged: opts.SandboxSyncOutChanged,
		Apply:          opts.SandboxApply,
		ApplyChanged:   opts.SandboxApplyChanged,
	})

	req := autoSandboxRequest{
		JSON:           opts.JSON,
		Args:           append([]string(nil), args...),
		SandboxName:    strings.TrimSpace(opts.SandboxName),
		SandboxHostID:  targetFlags.HostID,
		SandboxRuntime: targetFlags.RuntimeDriver,
		Flags:          opts,
		SyncOut:        syncOut,
		Security:       runSandboxSecurityRequest(),
	}
	req.RemoteCommand = buildAutoSandboxRemoteCommand(req)
	return req, nil
}

func runAutoSandboxWithWriter(ctx context.Context, cmd *cobra.Command, args []string, projectDir string, opts autoSandboxOptions, out, errOut io.Writer, deps autoSandboxDeps) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if out == nil {
		out = io.Discard
	}
	if errOut == nil {
		errOut = io.Discard
	}

	req, err := parseAutoSandboxRequest(args, opts)
	if err != nil {
		if opts.JSON {
			return outputAutoSandboxJSONErrorForCommand(cmd, out, args, opts, err.Error())
		}
		return autoSandboxExitValidation(cmd, err)
	}

	projectDir = strings.TrimSpace(projectDir)
	if projectDir == "" {
		projectDir = "."
	}
	absProjectDir, err := filepath.Abs(projectDir)
	if err != nil {
		err := fmt.Errorf("resolve project directory: %w", err)
		if opts.JSON {
			return outputAutoSandboxJSONErrorForCommand(cmd, out, args, opts, err.Error())
		}
		return err
	}
	req.ProjectDir = filepath.Clean(absProjectDir)
	if opts.DryRun {
		securitySettings, err := loadConfiguredSandboxSecuritySettings(req.ProjectDir, req.SandboxRuntime)
		if err != nil {
			err = fmt.Errorf("load sandbox security config: %w", err)
			if opts.JSON {
				return outputAutoSandboxJSONErrorForCommand(cmd, out, args, opts, err.Error())
			}
			return err
		}
		sourceMarkdown := ""
		if len(req.Args) > 0 {
			sourceMarkdown = req.Args[0]
		}
		entryMode := determineAutoEntryMode(sourceMarkdown)
		preview := newSandboxDryRunPreview(
			sandbox.SandboxLeasePurposeAuto,
			req.SandboxName,
			req.SandboxHostID,
			req.SandboxRuntime,
			opts.Base,
			req.SyncOut,
			securitySettings.Request,
			string(entryMode),
		)
		return renderSandboxDryRunPreview(out, opts.JSON, preview)
	}

	deps = normalizeAutoSandboxDeps(deps)
	startedAt := deps.now().UTC()
	req.ExecutionID = deps.newExecutionID(startedAt)
	store, storeErr := deps.defaultStore()
	if storeErr != nil {
		err := fmt.Errorf("open sandbox execution store: %w", storeErr)
		if opts.JSON {
			return outputAutoSandboxJSONErrorForCommand(cmd, out, args, opts, err.Error())
		}
		return err
	}

	securitySettings, err := loadConfiguredSandboxSecuritySettings(req.ProjectDir, req.SandboxRuntime)
	if err != nil {
		err = fmt.Errorf("load sandbox security config: %w", err)
		if opts.JSON {
			return outputAutoSandboxJSONErrorForCommand(cmd, out, args, opts, err.Error())
		}
		return err
	}
	req.Security = securitySettings.Request
	req.SecurityReadinessGateMode = securitySettings.ReadinessGateMode
	req.RemoteCommand = buildAutoSandboxRemoteCommand(req)
	if err := saveAutoSandboxManifest(store, req, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		if opts.JSON {
			return outputAutoSandboxJSONErrorForCommand(cmd, out, args, opts, err.Error())
		}
		return err
	}

	failBeforeRemote := func(cause error) error {
		finishedAt := deps.now().UTC()
		applyAutoSandboxSecurityReadinessGateError(&req, cause)
		_ = saveAutoSandboxManifest(store, req, sandboxexecution.StatusFailed, startedAt, &finishedAt, nil)
		if opts.JSON {
			return outputAutoSandboxJSONErrorWithReadinessGateForCommand(cmd, out, args, opts, cause.Error(), sandboxCommandSecurityReadinessGateDecisionFromError(cause))
		}
		return autoSandboxExitValidation(cmd, cause)
	}

	env, err := autoSandboxExecutionEnv(ctx)
	if err != nil {
		return failBeforeRemote(err)
	}
	req.Env = env

	if err := prepareAutoSandboxRequest(ctx, &req, deps); err != nil {
		return failBeforeRemote(err)
	}
	req.RemoteCommand = buildAutoSandboxRemoteCommand(req)
	if err := saveAutoSandboxManifest(store, req, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		return failBeforeRemote(err)
	}

	var target *sandbox.SandboxState
	commandOut := out
	var capturedJSON bytes.Buffer
	augmentJSON := opts.JSON
	if augmentJSON {
		commandOut = &capturedJSON
	}
	execResult, execErr := deps.execute(ctx, req, commandOut, errOut, autoSandboxExecutionHooks{
		OnTargetReady: func(ready *sandbox.SandboxState) error {
			target = ready
			if target != nil && strings.TrimSpace(req.SandboxName) == "" {
				req.SandboxName = strings.TrimSpace(target.Name)
			}
			if err := persistSandboxCommandSelectedState(sandboxCommandStatePersistenceRequest{
				SandboxHostID:  req.SandboxHostID,
				SandboxRuntime: req.SandboxRuntime,
				Target:         target,
				Workspace:      req.Workspace,
				Save:           deps.persistSandboxState,
			}); err != nil {
				return err
			}
			if err := saveAutoSandboxManifest(store, req, sandboxexecution.StatusRunning, startedAt, nil, target); err != nil {
				return err
			}
			return enforceSandboxExecutionSecurityReadinessGate(store, req.ExecutionID)
		},
		OnWorkerJobUpdate: func(reference *sandboxexecution.WorkerJobReference) error {
			req.WorkerJob = sandboxexecution.SanitizeWorkerJobReference(reference)
			req.Finalization = updateSandboxWorkerJobFinalization(
				req.Finalization,
				req.WorkerJob,
				req.SyncOut.Enabled,
				deps.now().UTC(),
			)
			return persistSandboxWorkerJobUpdate(
				store,
				req.ExecutionID,
				req.WorkerJob,
				req.SyncOut.Enabled,
				deps.now().UTC(),
			)
		},
	})
	if execResult.Result != nil {
		if target == nil {
			target = sandboxStateFromRuntimeTarget(execResult.Result.Target)
		}
		if strings.TrimSpace(req.SandboxName) == "" {
			req.SandboxName = strings.TrimSpace(target.Name)
		}
	}
	if len(execResult.PreparedCommand) > 0 {
		req.RemoteCommand = append([]string(nil), execResult.PreparedCommand...)
	} else if execResult.Result != nil && len(execResult.Result.Command.Command) > 0 {
		req.RemoteCommand = append([]string(nil), execResult.Result.Command.Command...)
	}
	if execErr != nil {
		if phaseErr, ok := sandboxexec.AsPhaseError(execErr); ok && phaseErr.Target != nil && target == nil {
			target = phaseErr.Target
			if strings.TrimSpace(req.SandboxName) == "" {
				req.SandboxName = strings.TrimSpace(target.Name)
			}
		}
		applyAutoSandboxSecurityReadinessGateError(&req, execErr)
	}
	if isSandboxWorkerJobDetachedError(execErr) {
		return execErr
	}
	if req.WorkerJob != nil {
		if finalizationErr := finalizeAutoSandboxWorkerJob(
			ctx,
			store,
			req,
			execResult,
			target,
			capturedJSON.Bytes(),
			deps,
		); finalizationErr != nil {
			execErr = errors.Join(execErr, finalizationErr)
		}
		if augmentJSON && execResult.RemoteStarted {
			if outputErr := outputSandboxAugmentedJSON(out, capturedJSON.Bytes(), store, req.ExecutionID); outputErr != nil {
				execErr = errors.Join(execErr, outputErr)
			}
		}
		if execErr != nil {
			if opts.JSON && !execResult.RemoteStarted {
				return outputAutoSandboxJSONErrorWithReadinessGateForCommand(cmd, out, args, opts, execErr.Error(), sandboxCommandSecurityReadinessGateDecisionFromError(execErr))
			}
			return execErr
		}
		return nil
	}

	if isSandboxRunPhaseError(execErr) {
		_ = collectAutoSandboxRecoveryAfterCommandFailure(ctx, store, req, execResult, target)
	}
	remoteArchivePath := ""
	if execErr == nil {
		remoteArchivePath, err = autoSandboxRemoteArchivePath(capturedJSON.Bytes(), execResult.StdoutSummary)
		if err != nil {
			execErr = fmt.Errorf("read remote auto archive path: %w", err)
		}
	}
	if execErr == nil {
		if collectErr := collectAutoSandboxCoreStateArtifacts(ctx, store, req, execResult, remoteArchivePath); collectErr != nil {
			execErr = collectErr
		}
	}
	if execErr == nil {
		if collectErr := collectAutoSandboxGeneratedArtifacts(ctx, store, req, execResult); collectErr != nil {
			execErr = collectErr
		}
	}
	if execErr == nil {
		if collectErr := collectAutoSandboxOutputSummaryArtifacts(store, req, execResult, target); collectErr != nil {
			execErr = collectErr
		}
	}
	if execErr == nil {
		if applyErr := applyAutoSandboxSyncOut(ctx, store, req, deps); applyErr != nil {
			execErr = applyErr
		}
	}
	leaseRelease := sandboxCommandLeaseReleaseTracker{releaseLease: deps.releaseLease}
	leaseRelease.observe(target)
	if releaseErr := leaseRelease.release(); releaseErr != nil {
		execErr = errors.Join(execErr, releaseErr)
	}

	finishedAt := deps.now().UTC()
	status := sandboxexecution.StatusSucceeded
	if execErr != nil {
		status = sandboxexecution.StatusFailed
	}
	if manifestErr := saveAutoSandboxManifest(store, req, status, startedAt, &finishedAt, target); manifestErr != nil && execErr == nil {
		execErr = manifestErr
	}
	if augmentJSON && execResult.RemoteStarted {
		if outputErr := outputSandboxAugmentedJSON(out, capturedJSON.Bytes(), store, req.ExecutionID); outputErr != nil {
			execErr = errors.Join(execErr, outputErr)
		}
	}
	if execErr != nil {
		if opts.JSON && !execResult.RemoteStarted {
			return outputAutoSandboxJSONErrorWithReadinessGateForCommand(cmd, out, args, opts, execErr.Error(), sandboxCommandSecurityReadinessGateDecisionFromError(execErr))
		}
		return execErr
	}
	return nil
}

func normalizeAutoSandboxDeps(deps autoSandboxDeps) autoSandboxDeps {
	customDefaultStore := deps.defaultStore != nil && !deps.durableLeaseStore
	customResolveDefault := deps.resolveDefault != nil
	customRuntimeResolver := deps.resolveRuntimeDriver != nil
	if deps.defaultStore == nil {
		deps.defaultStore = defaultAutoSandboxDeps.defaultStore
		deps.durableLeaseStore = defaultAutoSandboxDeps.durableLeaseStore
		customDefaultStore = !deps.durableLeaseStore
	}
	if deps.newExecutionID == nil {
		deps.newExecutionID = defaultAutoSandboxDeps.newExecutionID
	}
	if deps.now == nil {
		deps.now = defaultAutoSandboxDeps.now
	}
	if deps.planWorkspace == nil {
		deps.planWorkspace = defaultAutoSandboxDeps.planWorkspace
	}
	if deps.loadSandbox == nil {
		deps.loadSandbox = defaultAutoSandboxDeps.loadSandbox
	}
	if deps.resolveDefault == nil {
		deps.resolveDefault = defaultAutoSandboxDeps.resolveDefault
	}
	if deps.listSandboxes == nil {
		if customResolveDefault {
			deps.listSandboxes = sandboxCommandListSandboxesFromDefault(deps.resolveDefault)
		} else {
			deps.listSandboxes = defaultAutoSandboxDeps.listSandboxes
		}
	}
	if deps.listHosts == nil {
		deps.listHosts = defaultAutoSandboxDeps.listHosts
	}
	if deps.listLeases == nil {
		deps.listLeases = sandboxCommandDefaultLeaseLister(deps.now, customDefaultStore)
	}
	if deps.provision == nil {
		deps.provision = defaultAutoSandboxDeps.provision
	}
	if deps.acquireLease == nil {
		deps.acquireLease = sandboxCommandDefaultLeaseAcquirer(deps.now, customDefaultStore)
	}
	if deps.releaseLease == nil {
		deps.releaseLease = sandboxCommandDefaultLeaseReleaser(deps.now, customDefaultStore)
	}
	if deps.resolveProvider == nil {
		deps.resolveProvider = defaultAutoSandboxDeps.resolveProvider
	}
	if deps.resolveRuntimeDriver == nil {
		deps.resolveRuntimeDriver = func(target sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return sandboxRuntimeDriverFromTarget(target, deps.resolveProvider)
		}
	}
	deps.customRuntimeResolver = customRuntimeResolver
	if deps.runProviderExecWithEnv == nil {
		deps.runProviderExecWithEnv = defaultAutoSandboxDeps.runProviderExecWithEnv
	}
	if deps.runProviderScript == nil {
		deps.runProviderScript = defaultAutoSandboxDeps.runProviderScript
	}
	if deps.engineAuthFiles == nil {
		deps.engineAuthFiles = defaultAutoSandboxDeps.engineAuthFiles
	}
	if deps.bootstrap == nil {
		deps.bootstrap = defaultAutoSandboxDeps.bootstrap
	}
	if deps.materializeWorkspace == nil {
		deps.materializeWorkspace = sandboxexec.MaterializeBundleWorkspace
	}
	if deps.prepareCommandContext == nil {
		deps.prepareCommandContext = prepareSandboxCommandContextRuntime
	}
	if deps.workerJobWait == nil {
		deps.workerJobWait = waitForSandboxWorkerJobPoll
	}
	if deps.execute == nil {
		deps.execute = deps.executeAutoSandbox
	}
	return deps
}

func prepareAutoSandboxRequest(ctx context.Context, req *autoSandboxRequest, deps autoSandboxDeps) error {
	plan, err := deps.planWorkspace(ctx, sandboxworkspace.Request{
		ProjectDir:      req.ProjectDir,
		WorkspaceMode:   sandbox.SandboxWorkspaceModeClone,
		PreferredBranch: strings.TrimSpace(req.Flags.Base),
	})
	if err != nil {
		return fmt.Errorf("plan sandbox workspace: %w", err)
	}
	repoRemote := strings.TrimSpace(plan.Repository)
	if repoRemote == "" {
		return fmt.Errorf("resolve repository remote: remote.origin.url is required for sandbox execution")
	}
	branchName := strings.TrimSpace(plan.Branch)
	baseBranch := strings.TrimSpace(req.Flags.Base)
	if baseBranch == "" {
		baseBranch = branchName
	}
	if baseBranch == "" {
		return fmt.Errorf("resolve base branch: current branch is required for sandbox execution; pass --base explicitly")
	}

	plan = sandboxWorkspacePlanForCommand(plan, req.ProjectDir, sandbox.SandboxWorkspaceInputSourceRemoteRef)
	req.RepoRemote = repoRemote
	req.BaseBranch = baseBranch
	req.RunBranch = branchName
	workspace := sandboxWorkspaceMetadataFromPlan(plan, sandbox.SandboxWorkspaceInputSourceRemoteRef, baseBranch)
	req.Workspace = &workspace
	req.WorkspacePlan = cloneSandboxWorkspacePlan(plan)
	if inputSource := strings.TrimSpace(plan.InputSource); inputSource != "" && inputSource != sandbox.SandboxWorkspaceInputSourceRemoteRef {
		if inputSource == sandbox.SandboxWorkspaceInputSourceGitBundle {
			return prepareAutoSandboxWorkDir(req)
		}
		return fmt.Errorf("plan sandbox workspace: unsupported clone input source %q for hal auto --sandbox", inputSource)
	}

	return prepareAutoSandboxWorkDir(req)
}

func prepareAutoSandboxWorkDir(req *autoSandboxRequest) error {
	record := factory.RunRecord{
		RunID:      req.ExecutionID,
		RepoPath:   req.ProjectDir,
		RepoRemote: req.RepoRemote,
		BranchName: req.RunBranch,
		BaseBranch: req.BaseBranch,
	}
	req.WorkDir = factorySandboxRemoteWorkspaceDir(record)
	if strings.TrimSpace(req.WorkDir) == "" {
		return errFactorySandboxWorkspaceRequired
	}
	return nil
}

func (deps autoSandboxDeps) executeAutoSandbox(ctx context.Context, req autoSandboxRequest, out, errOut io.Writer, hooks autoSandboxExecutionHooks) (autoSandboxExecutionResult, error) {
	prepOut := out
	if req.JSON {
		prepOut = errOut
	}
	var remoteStarted bool
	var preparedCommand []string
	var runtimeDriver sandboxruntime.Driver
	var selectedTarget *sandbox.SandboxState
	var provider sandbox.Provider
	var stdoutSummary strings.Builder
	var stderrSummary strings.Builder
	ensureProvider := func(providerName string) (sandbox.Provider, error) {
		if provider != nil {
			return provider, nil
		}
		resolved, err := deps.resolveProvider(providerName)
		if err != nil {
			return nil, err
		}
		provider = resolved
		return provider, nil
	}
	result, err := sandboxexec.Run(ctx, sandboxexec.CommandRequest{
		Purpose:     sandbox.SandboxLeasePurposeAuto,
		ProjectDir:  req.ProjectDir,
		SandboxName: req.SandboxName,
		Command:     append([]string(nil), req.RemoteCommand...),
		WorkDir:     req.WorkDir,
		Env:         req.Env,
		Security:    req.Security,
		Stdout:      out,
		Stderr:      errOut,
		SetupStdout: prepOut,
		SetupStderr: prepOut,
	}, sandboxexec.Dependencies{
		ResolveTarget: func(ctx context.Context, _ sandboxexec.TargetRequest) (*sandbox.SandboxState, error) {
			target, err := deps.resolveAutoSandboxTarget(ctx, req, prepOut)
			if err == nil {
				selectedTarget = target
			}
			return target, err
		},
		ResolveDriver: func(_ context.Context, target sandboxruntime.Target) (sandboxruntime.Driver, error) {
			driver, handled, err := deps.resolveAutoSandboxRuntimeDriver(req, target, selectedTarget)
			if !handled {
				driver, err = deps.resolveRuntimeDriver(target)
			}
			if err == nil {
				runtimeDriver = driver
			}
			return driver, err
		},
		OnTargetReady: func(_ context.Context, target *sandbox.SandboxState) error {
			if hooks.OnTargetReady == nil {
				return nil
			}
			return hooks.OnTargetReady(target)
		},
		PrepareWorkspace: func(ctx context.Context, prep sandboxexec.PrepareContext, _ *sandboxexec.CommandRequest) error {
			if isGitBundleWorkspace(req.Workspace) {
				_, err := deps.materializeWorkspace(ctx, prep, sandboxexec.WorkspaceMaterializationRequest{
					Workspace:    *req.Workspace,
					Plan:         req.WorkspacePlan,
					ProjectDir:   req.ProjectDir,
					WorkspaceDir: req.WorkDir,
				})
				if err != nil {
					return err
				}
				if deps.prepareCommandContext == nil {
					return fmt.Errorf("sandbox command context dependency is required")
				}
				if _, err := deps.prepareCommandContext(ctx, prep, req.ProjectDir, req.WorkDir, prepOut); err != nil {
					return err
				}
				if autoSandboxWorkerRuntimeRouteSelected(req, prep.Target, selectedTarget) {
					return deps.prepareAutoSandboxInputsRuntime(ctx, &req, prep)
				}
				provider, err := ensureProvider(prep.Target.Provider)
				if err != nil {
					return err
				}
				return deps.prepareAutoSandboxInputs(ctx, &req, provider, prep, prepOut)
			}
			if autoSandboxWorkerRuntimeRouteSelected(req, prep.Target, selectedTarget) {
				if err := deps.bootstrapAutoSandboxWorkspaceRuntime(ctx, req, prep, prepOut); err != nil {
					return err
				}
				if deps.prepareCommandContext != nil {
					if _, err := deps.prepareCommandContext(ctx, prep, req.ProjectDir, req.WorkDir, prepOut); err != nil {
						return err
					}
				}
				return deps.prepareAutoSandboxInputsRuntime(ctx, &req, prep)
			}
			provider, err := ensureProvider(prep.Target.Provider)
			if err != nil {
				return err
			}
			if err := deps.bootstrapAutoSandboxWorkspace(ctx, req, provider, prep, prepOut); err != nil {
				return err
			}
			if deps.prepareCommandContext != nil {
				if _, err := deps.prepareCommandContext(ctx, prep, req.ProjectDir, req.WorkDir, prepOut); err != nil {
					return err
				}
			}
			return deps.prepareAutoSandboxInputs(ctx, &req, provider, prep, prepOut)
		},
		PrepareAuth: func(ctx context.Context, prep sandboxexec.PrepareContext, _ *sandboxexec.CommandRequest) error {
			if autoSandboxWorkerRuntimeRouteSelected(req, prep.Target, selectedTarget) {
				return factorySandboxSyncEngineAuthRuntime(ctx, prep, factorySandboxExecutorDeps{
					engineAuthFiles: deps.engineAuthFiles,
				})
			}
			provider, err := ensureProvider(prep.Target.Provider)
			if err != nil {
				return err
			}
			return factorySandboxSyncEngineAuth(ctx, provider, sandboxStateFromRuntimeTarget(prep.Target), prepOut, factorySandboxExecutorDeps{
				runProviderExecWithEnv: deps.runProviderExecWithEnv,
				runProviderScript:      deps.runProviderScript,
				engineAuthFiles:        deps.engineAuthFiles,
			})
		},
		PrepareCommand: func(_ context.Context, _ sandboxexec.PrepareContext, command *sandboxexec.CommandRequest) error {
			command.Command = append([]string(nil), req.RemoteCommand...)
			preparedCommand = append([]string(nil), command.Command...)
			return nil
		},
		RunCommand: func(ctx context.Context, run sandboxexec.RunContext, command sandboxexec.CommandRequest) error {
			return runSandboxWorkerJobOrSync(ctx, sandboxWorkerJobCommandRequest{
				ExecutionID:  req.ExecutionID,
				UseWorkerJob: autoSandboxWorkerJobRouteSelected(req, run.Target, selectedTarget),
				HostID:       sandboxWorkerJobSelectedHostID(selectedTarget),
				Run:          run,
				Command:      command,
				Persist:      hooks.OnWorkerJobUpdate,
				Wait:         deps.workerJobWait,
			})
		},
		HandleEvent: func(_ context.Context, event sandboxexec.Event) error {
			if event.Type == sandboxexec.EventCommandOutput && event.Stream == sandboxexec.StreamStdout {
				remoteStarted = true
			}
			if event.Type == sandboxexec.EventCommandOutput {
				switch event.Stream {
				case sandboxexec.StreamStdout:
					appendSandboxOutputSummaryLine(&stdoutSummary, event.Line)
				case sandboxexec.StreamStderr:
					appendSandboxOutputSummaryLine(&stderrSummary, event.Line)
				}
			}
			return nil
		},
	})
	return autoSandboxExecutionResult{
		Result:          result,
		RuntimeDriver:   runtimeDriver,
		RemoteStarted:   remoteStarted,
		PreparedCommand: preparedCommand,
		StdoutSummary:   stdoutSummary.String(),
		StderrSummary:   stderrSummary.String(),
	}, err
}

func (deps autoSandboxDeps) resolveAutoSandboxRuntimeDriver(req autoSandboxRequest, target sandboxruntime.Target, selectedTarget *sandbox.SandboxState) (sandboxruntime.Driver, bool, error) {
	if !autoSandboxWorkerRuntimeRouteSelected(req, target, selectedTarget) {
		return nil, false, nil
	}
	resolver := deps.resolveWorkerRuntime
	if resolver == nil && !deps.customRuntimeResolver {
		resolver = func(req sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
			return sandboxWorkerRuntimeDriverFromTarget(req, sandboxWorkerRuntimeDriverFactories{})
		}
	}
	if resolver == nil {
		return nil, false, nil
	}
	driver, err := resolver(sandboxWorkerRuntimeRequest{
		Target: target,
		Host:   selectedTarget.Host,
	})
	return driver, true, err
}

func autoSandboxWorkerRuntimeRouteSelected(req autoSandboxRequest, target sandboxruntime.Target, selectedTarget *sandbox.SandboxState) bool {
	return sandboxWorkerRuntimeRouteSelected(req.SandboxHostID, req.SandboxRuntime, target, selectedTarget)
}

func autoSandboxRemoteArchivePath(remoteJSON []byte, stdoutSummary string) (string, error) {
	archivePath := ""
	if len(bytes.TrimSpace(remoteJSON)) > 0 {
		var remoteResult struct {
			Steps struct {
				Archive struct {
					Path string `json:"path"`
				} `json:"archive"`
			} `json:"steps"`
		}
		decoder := json.NewDecoder(bytes.NewReader(remoteJSON))
		if err := decoder.Decode(&remoteResult); err == nil {
			var extra any
			if err := decoder.Decode(&extra); err == io.EOF {
				archivePath = strings.TrimSpace(remoteResult.Steps.Archive.Path)
			}
		}
	}
	if archivePath == "" {
		const archivedStatePrefix = "Archived state to "
		for _, line := range strings.Split(stdoutSummary, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, archivedStatePrefix) {
				archiveName := strings.TrimSpace(strings.TrimPrefix(line, archivedStatePrefix))
				if archiveName != "" {
					archivePath = pathpkg.Join(template.HalDir, "archive", archiveName)
				}
			}
		}
	}
	if err := sandboxexecution.ValidateAutoArchivePath(archivePath); err != nil {
		return "", err
	}
	return archivePath, nil
}

func collectAutoSandboxCoreStateArtifacts(ctx context.Context, store sandboxexecution.Store, req autoSandboxRequest, result autoSandboxExecutionResult, remoteArchivePath string) error {
	if result.Result == nil || result.RuntimeDriver == nil {
		return nil
	}
	_, err := sandboxexecution.CollectCoreStateArtifacts(ctx, sandboxexecution.CoreStateCollectionRequest{
		ExecutionID:        req.ExecutionID,
		Store:              store,
		Runtime:            result.RuntimeDriver,
		Target:             result.Result.Target,
		Purpose:            sandboxexecution.PurposeAuto,
		RemoteWorkspaceDir: req.WorkDir,
		RemoteArchivePath:  remoteArchivePath,
	})
	if err != nil {
		if handled, warningErr := appendSandboxArtifactCopyWarning(store, req.ExecutionID, err); handled {
			if warningErr != nil {
				return fmt.Errorf("collect auto sandbox core state artifacts: %w", warningErr)
			}
			return nil
		}
		return fmt.Errorf("collect auto sandbox core state artifacts: %w", err)
	}
	return nil
}

func collectAutoSandboxGeneratedArtifacts(ctx context.Context, store sandboxexecution.Store, req autoSandboxRequest, result autoSandboxExecutionResult) error {
	if result.Result == nil || result.RuntimeDriver == nil {
		return nil
	}
	collectionReq := sandboxexecution.RecoveryArtifactCollectionRequest{
		ExecutionID:        req.ExecutionID,
		Store:              store,
		Runtime:            result.RuntimeDriver,
		Target:             result.Result.Target,
		RemoteWorkspaceDir: req.WorkDir,
	}
	if _, err := sandboxexecution.CollectRecoveryArtifactsBestEffort(ctx, collectionReq); err != nil {
		return fmt.Errorf("collect auto sandbox recovery artifacts: %w", err)
	}
	if req.SyncOut.Enabled {
		if _, err := sandboxexecution.CollectUncommittedSyncOutArtifactBestEffort(ctx, sandboxexecution.UncommittedSyncOutCollectionRequest{
			ExecutionID:        req.ExecutionID,
			Store:              store,
			Runtime:            result.RuntimeDriver,
			Target:             result.Result.Target,
			RemoteWorkspaceDir: req.WorkDir,
		}); err != nil {
			return fmt.Errorf("collect auto sandbox uncommitted sync-out artifact: %w", err)
		}
		if _, err := sandboxexecution.CollectUntrackedSyncOutArtifactsBestEffort(ctx, sandboxexecution.UntrackedSyncOutCollectionRequest{
			ExecutionID:        req.ExecutionID,
			Store:              store,
			Runtime:            result.RuntimeDriver,
			Target:             result.Result.Target,
			RemoteWorkspaceDir: req.WorkDir,
		}); err != nil {
			return fmt.Errorf("collect auto sandbox untracked sync-out artifacts: %w", err)
		}
		if _, err := sandboxexecution.CollectCommittedSyncOutArtifactBestEffort(ctx, sandboxexecution.CommittedSyncOutCollectionRequest{
			ExecutionID:        req.ExecutionID,
			Store:              store,
			Runtime:            result.RuntimeDriver,
			Target:             result.Result.Target,
			RemoteWorkspaceDir: req.WorkDir,
			SyncRef:            sandboxCommittedSyncOutBaseRef(req.Workspace, req.BaseBranch),
		}); err != nil {
			return fmt.Errorf("collect auto sandbox committed sync-out artifact: %w", err)
		}
	}
	if _, err := sandboxexecution.CollectReportsArchiveArtifacts(ctx, sandboxexecution.ReportsArchiveCollectionRequest{
		ExecutionID:        req.ExecutionID,
		Store:              store,
		Runtime:            result.RuntimeDriver,
		Target:             result.Result.Target,
		RemoteWorkspaceDir: req.WorkDir,
	}); err != nil {
		if handled, warningErr := appendSandboxArtifactCopyWarning(store, req.ExecutionID, err); handled {
			if warningErr != nil {
				return fmt.Errorf("collect auto sandbox reports archive artifacts: %w", warningErr)
			}
			return nil
		}
		return fmt.Errorf("collect auto sandbox reports archive artifacts: %w", err)
	}
	return nil
}

func collectAutoSandboxRecoveryAfterCommandFailure(ctx context.Context, store sandboxexecution.Store, req autoSandboxRequest, result autoSandboxExecutionResult, target *sandbox.SandboxState) error {
	if result.RuntimeDriver == nil {
		return nil
	}
	runtimeTarget, ok := autoSandboxRuntimeTargetForCollection(result, target)
	if !ok {
		return nil
	}
	var collectErr error
	if _, err := sandboxexecution.CollectRecoveryArtifactsBestEffort(ctx, sandboxexecution.RecoveryArtifactCollectionRequest{
		ExecutionID:        req.ExecutionID,
		Store:              store,
		Runtime:            result.RuntimeDriver,
		Target:             runtimeTarget,
		RemoteWorkspaceDir: req.WorkDir,
	}); err != nil {
		collectErr = errors.Join(collectErr, fmt.Errorf("collect auto sandbox recovery artifacts after command failure: %w", err))
	}
	if !req.SyncOut.Enabled {
		return collectErr
	}
	if _, err := sandboxexecution.CollectUncommittedSyncOutArtifactBestEffort(ctx, sandboxexecution.UncommittedSyncOutCollectionRequest{
		ExecutionID:        req.ExecutionID,
		Store:              store,
		Runtime:            result.RuntimeDriver,
		Target:             runtimeTarget,
		RemoteWorkspaceDir: req.WorkDir,
	}); err != nil {
		collectErr = errors.Join(collectErr, fmt.Errorf("collect auto sandbox uncommitted sync-out artifact after command failure: %w", err))
	}
	if _, err := sandboxexecution.CollectUntrackedSyncOutArtifactsBestEffort(ctx, sandboxexecution.UntrackedSyncOutCollectionRequest{
		ExecutionID:        req.ExecutionID,
		Store:              store,
		Runtime:            result.RuntimeDriver,
		Target:             runtimeTarget,
		RemoteWorkspaceDir: req.WorkDir,
	}); err != nil {
		collectErr = errors.Join(collectErr, fmt.Errorf("collect auto sandbox untracked sync-out artifacts after command failure: %w", err))
	}
	if _, err := sandboxexecution.CollectCommittedSyncOutArtifactBestEffort(ctx, sandboxexecution.CommittedSyncOutCollectionRequest{
		ExecutionID:        req.ExecutionID,
		Store:              store,
		Runtime:            result.RuntimeDriver,
		Target:             runtimeTarget,
		RemoteWorkspaceDir: req.WorkDir,
		SyncRef:            sandboxCommittedSyncOutBaseRef(req.Workspace, req.BaseBranch),
	}); err != nil {
		collectErr = errors.Join(collectErr, fmt.Errorf("collect auto sandbox committed sync-out artifact after command failure: %w", err))
	}
	if err := persistFailedSandboxSyncOutHandoff(store, req.ExecutionID); err != nil {
		collectErr = errors.Join(collectErr, err)
	}
	return collectErr
}

func autoSandboxRuntimeTargetForCollection(result autoSandboxExecutionResult, target *sandbox.SandboxState) (sandboxruntime.Target, bool) {
	if result.Result != nil {
		return result.Result.Target, true
	}
	if target != nil {
		return sandboxRuntimeTargetFromState(target), true
	}
	return sandboxruntime.Target{}, false
}

func collectAutoSandboxOutputSummaryArtifacts(store sandboxexecution.Store, req autoSandboxRequest, result autoSandboxExecutionResult, target *sandbox.SandboxState) error {
	stdoutSummary := sanitizeSandboxOutputSummary(result.StdoutSummary, target)
	stderrSummary := sanitizeSandboxOutputSummary(result.StderrSummary, target)
	if strings.TrimSpace(stdoutSummary) == "" && strings.TrimSpace(stderrSummary) == "" {
		return nil
	}
	if _, err := sandboxexecution.SaveCommandOutputSummaryArtifacts(sandboxexecution.CommandOutputSummaryArtifactsRequest{
		ExecutionID:   req.ExecutionID,
		Store:         store,
		StdoutSummary: stdoutSummary,
		StderrSummary: stderrSummary,
	}); err != nil {
		return fmt.Errorf("collect auto sandbox output summary artifacts: %w", err)
	}
	return nil
}

func (deps autoSandboxDeps) resolveAutoSandboxTarget(ctx context.Context, req autoSandboxRequest, out io.Writer) (*sandbox.SandboxState, error) {
	listSandboxes := deps.listSandboxes
	if listSandboxes == nil && deps.resolveDefault != nil {
		listSandboxes = sandboxCommandListSandboxesFromDefault(deps.resolveDefault)
	}
	target, err := resolveSandboxCommandExecutionTarget(
		ctx,
		sandboxCommandTargetRequest{
			Purpose:                   sandbox.SandboxLeasePurposeAuto,
			SandboxName:               req.SandboxName,
			SandboxHostID:             req.SandboxHostID,
			SandboxRuntime:            req.SandboxRuntime,
			SecurityReadinessGateMode: req.SecurityReadinessGateMode,
			ProjectDir:                req.ProjectDir,
			Repository:                req.RepoRemote,
			Branch:                    req.RunBranch,
			ProvisionRepository:       req.RepoRemote,
			Out:                       out,
		},
		sandboxCommandTargetDeps{
			loadSandbox:    deps.loadSandbox,
			listSandboxes:  listSandboxes,
			listHosts:      deps.listHosts,
			resolveDefault: deps.resolveDefault,
			provision:      deps.provision,
		},
		sandboxCommandScheduledTargetRequest{
			Purpose:        sandbox.SandboxLeasePurposeAuto,
			SandboxName:    req.SandboxName,
			SandboxHostID:  req.SandboxHostID,
			SandboxRuntime: req.SandboxRuntime,
			ProjectDir:     req.ProjectDir,
			Repository:     req.RepoRemote,
			Branch:         req.RunBranch,
			RunID:          req.ExecutionID,
			Workspace:      req.Workspace,
		},
		sandboxCommandScheduledTargetDeps{
			listHosts:    deps.listHosts,
			listLeases:   deps.listLeases,
			now:          deps.now,
			acquireLease: deps.acquireLease,
		},
	)
	if err != nil {
		return nil, err
	}
	if !sandboxWorkerRoutingRequested(req.SandboxHostID, req.SandboxRuntime) {
		target = sandboxCommandSSHMachineCompatWorkerTarget(target)
	}
	return target, nil
}

func (deps autoSandboxDeps) bootstrapAutoSandboxWorkspace(ctx context.Context, req autoSandboxRequest, provider sandbox.Provider, prep sandboxexec.PrepareContext, out io.Writer) error {
	bootstrapReq := factory.BootstrapRequest{
		RepositoryURL: req.RepoRemote,
		BaseBranch:    req.BaseBranch,
		RunBranch:     req.RunBranch,
		WorkspaceDir:  req.WorkDir,
		Options: factory.BootstrapOptions{
			RefreshHal:    true,
			ExactUpstream: true,
		},
	}
	connectInfo := sandboxConnectInfoFromRuntimeTarget(prep.Target)
	_, err := deps.bootstrap(ctx, bootstrapReq, factory.BootstrapDeps{
		Executor: &factorySandboxBootstrapExecutor{
			provider:               provider,
			connectInfo:            connectInfo,
			runProviderExecWithEnv: deps.runProviderExecWithEnv,
			out:                    out,
			outputRedact:           factory.NewBootstrapSanitizer(bootstrapReq).SanitizeString,
		},
		Now: deps.now,
		RepoExists: func(path string) (bool, error) {
			return factorySandboxRemoteRepoExists(ctx, provider, connectInfo, deps.runProviderScript, path, req.RepoRemote)
		},
	})
	return err
}

func (deps autoSandboxDeps) bootstrapAutoSandboxWorkspaceRuntime(ctx context.Context, req autoSandboxRequest, prep sandboxexec.PrepareContext, out io.Writer) error {
	bootstrapReq := factory.BootstrapRequest{
		RepositoryURL: req.RepoRemote,
		BaseBranch:    req.BaseBranch,
		RunBranch:     req.RunBranch,
		WorkspaceDir:  req.WorkDir,
		Options: factory.BootstrapOptions{
			RefreshHal:    true,
			ExactUpstream: true,
		},
	}
	_, err := sandboxRuntimeBootstrapWorkspace(ctx, bootstrapReq, prep, out, deps.now, deps.bootstrap)
	return err
}

func (deps autoSandboxDeps) prepareAutoSandboxInputsRuntime(ctx context.Context, req *autoSandboxRequest, prep sandboxexec.PrepareContext) error {
	if req == nil {
		return nil
	}
	if len(req.Args) > 0 {
		remotePath, changed, err := factorySandboxCopyInputRuntime(ctx, prep, req.ProjectDir, req.Args[0], req.WorkDir)
		if err != nil {
			return err
		}
		if changed {
			req.Args = append([]string{remotePath}, req.Args[1:]...)
		}
	}
	if reportPath := strings.TrimSpace(req.Flags.Report); reportPath != "" {
		remotePath, changed, err := factorySandboxCopyInputRuntime(ctx, prep, req.ProjectDir, reportPath, req.WorkDir)
		if err != nil {
			return err
		}
		if changed {
			req.Flags.Report = remotePath
		}
	}
	return nil
}

func (deps autoSandboxDeps) prepareAutoSandboxInputs(ctx context.Context, req *autoSandboxRequest, provider sandbox.Provider, prep sandboxexec.PrepareContext, out io.Writer) error {
	if req == nil {
		return nil
	}
	connectInfo := sandboxConnectInfoFromRuntimeTarget(prep.Target)
	if len(req.Args) > 0 {
		remotePath, changed, err := factorySandboxCopyInputToRemote(ctx, req.ProjectDir, req.Args[0], req.WorkDir, provider, connectInfo, out, factorySandboxExecutorDeps{
			runProviderScript: deps.runProviderScript,
		})
		if err != nil {
			return err
		}
		if changed {
			req.Args = append([]string{remotePath}, req.Args[1:]...)
		}
	}
	if reportPath := strings.TrimSpace(req.Flags.Report); reportPath != "" {
		remotePath, changed, err := factorySandboxCopyInputToRemote(ctx, req.ProjectDir, reportPath, req.WorkDir, provider, connectInfo, out, factorySandboxExecutorDeps{
			runProviderScript: deps.runProviderScript,
		})
		if err != nil {
			return err
		}
		if changed {
			req.Flags.Report = remotePath
		}
	}
	req.RemoteCommand = buildAutoSandboxRemoteCommand(*req)
	return nil
}

func saveAutoSandboxManifest(store sandboxexecution.Store, req autoSandboxRequest, status sandboxexecution.Status, startedAt time.Time, finishedAt *time.Time, target *sandbox.SandboxState) error {
	manifest := &sandboxexecution.Manifest{
		ID:                        req.ExecutionID,
		Purpose:                   sandboxexecution.PurposeAuto,
		SandboxName:               req.SandboxName,
		ProjectDir:                req.ProjectDir,
		Command:                   append([]string(nil), req.RemoteCommand...),
		WorkDir:                   req.WorkDir,
		Status:                    status,
		StartedAt:                 startedAt,
		FinishedAt:                finishedAt,
		Workspace:                 autoSandboxManifestWorkspace(req),
		Security:                  cloneSandboxSecurity(nil),
		NetworkProxySession:       sandboxManifestNetworkProxySession(req.NetworkProxySession),
		NetworkPolicyDecisionLogs: sandboxManifestNetworkPolicyDecisionLogs(req.NetworkPolicyDecisionLogs),
		WorkerJob:                 sandboxexecution.SanitizeWorkerJobReference(req.WorkerJob),
		Finalization:              cloneSandboxWorkerJobFinalization(req.Finalization),
	}
	applyAutoSandboxCredentialProxyMetadata(manifest, req)
	if target != nil {
		manifest.SandboxID = strings.TrimSpace(target.ID)
		if strings.TrimSpace(manifest.SandboxName) == "" {
			manifest.SandboxName = strings.TrimSpace(target.Name)
		}
		if selectedWorkerRootlessSandboxState(target) {
			manifest.Host = workerRootlessManifestHost(target.Host)
		} else {
			manifest.Host = cloneSandboxHost(target.Host)
		}
		manifest.Runtime = cloneSandboxRuntime(target.Runtime)
		manifest.Lease = sandboxLeaseRefFromState(target)
		if sandboxWorkerRoutingRequested(req.SandboxHostID, req.SandboxRuntime) {
			manifest.WorkerRouting = sandboxWorkerRoutingMetadataFromState(target)
		}
	}
	manifest.Security = sandboxManifestSecurity(req.Security, target)
	applyAutoSandboxCapabilityReadinessMetadata(manifest)
	manifest.Security = applyCommandSandboxSecurityReadinessGate(manifest.Security, req.SecurityReadinessGateMode, autoSandboxManifestSecurityReadinessGate(req, target))
	preserveSandboxManifestArtifacts(store, manifest)
	preserveSandboxManifestWorkerJobState(store, manifest)
	return store.SaveManifest(manifest)
}

func autoSandboxManifestSecurityReadinessGate(req autoSandboxRequest, target *sandbox.SandboxState) *sandbox.SandboxSecurityCapabilityReadinessGateDecision {
	if req.SecurityReadinessGate != nil {
		return sandbox.CloneSandboxSecurityCapabilityReadinessGateDecisionPtr(req.SecurityReadinessGate)
	}
	if target == nil || target.Security == nil {
		return nil
	}
	if target.Security.CapabilityReadiness == nil && target.Security.CapabilityReadinessDiagnostics == nil {
		return nil
	}
	return sandbox.CloneSandboxSecurityCapabilityReadinessGateDecisionPtr(target.Security.SecurityReadinessGate)
}

func autoSandboxManifestWorkspace(req autoSandboxRequest) *sandbox.SandboxWorkspace {
	if sandboxWorkerRoutingRequested(req.SandboxHostID, req.SandboxRuntime) {
		return sandboxCommandPersistentWorkspace(req.Workspace)
	}
	return cloneSandboxWorkspace(req.Workspace)
}

func applyAutoSandboxSecurityReadinessGateError(req *autoSandboxRequest, err error) {
	if req == nil {
		return
	}
	if decision := sandboxCommandTargetSelectionSecurityReadinessGateDecisionFromError(err); decision != nil {
		req.SecurityReadinessGateMode = decision.PolicyMode
		req.SecurityReadinessGate = decision
	}
}

func buildAutoSandboxRemoteCommand(req autoSandboxRequest) []string {
	flags := req.Flags
	command := []string{"hal", "auto"}
	for _, arg := range req.Args {
		if trimmed := strings.TrimSpace(arg); trimmed != "" {
			command = append(command, autoSandboxRemoteProjectPath(req.ProjectDir, trimmed))
		}
	}
	if flags.DryRun {
		command = append(command, "--dry-run")
	}
	if flags.Resume {
		command = append(command, "--resume")
	}
	if flags.NoCI {
		command = append(command, "--no-ci")
	}
	if flags.NoReview {
		command = append(command, "--no-review")
	}
	if flags.ModeChanged {
		command = append(command, "--mode", strings.TrimSpace(flags.Mode))
	}
	if flags.ReviewStreakChanged {
		command = append(command, "--review-streak", strconv.Itoa(flags.ReviewStreak))
	}
	if flags.ReviewMaxChanged {
		command = append(command, "--review-max", strconv.Itoa(flags.ReviewMax))
	}
	if flags.ReportChanged || strings.TrimSpace(flags.Report) != "" {
		if report := strings.TrimSpace(flags.Report); report != "" {
			command = append(command, "--report", autoSandboxRemoteProjectPath(req.ProjectDir, report))
		}
	}
	if flags.EngineChanged {
		if engineName := strings.TrimSpace(flags.Engine); engineName != "" {
			command = append(command, "--engine", engineName)
		}
	}
	if flags.BaseChanged {
		if base := strings.TrimSpace(flags.Base); base != "" {
			command = append(command, "--base", base)
		}
	}
	if flags.JSON {
		command = append(command, "--json")
	}
	return command
}

func autoSandboxRemoteProjectPath(projectDir string, value string) string {
	value = strings.TrimSpace(value)
	if value == "" || !filepath.IsAbs(value) {
		return value
	}
	projectDir = strings.TrimSpace(projectDir)
	if projectDir == "" {
		return value
	}
	rel, err := filepath.Rel(projectDir, value)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return value
	}
	return filepath.ToSlash(rel)
}

func outputAutoSandboxJSONError(out io.Writer, args []string, opts autoSandboxOptions, errMsg string) error {
	return outputAutoSandboxJSONErrorWithReadinessGate(out, args, opts, errMsg, nil)
}

func outputAutoSandboxJSONErrorForCommand(cmd *cobra.Command, out io.Writer, args []string, opts autoSandboxOptions, errMsg string) error {
	if err := outputAutoSandboxJSONError(out, args, opts, errMsg); err != nil {
		return err
	}
	return exitWithCode(cmd, ExitCodeValidation, nil)
}

func outputAutoSandboxJSONErrorWithReadinessGate(out io.Writer, args []string, opts autoSandboxOptions, errMsg string, gate *sandbox.SandboxSecurityCapabilityReadinessGateDecision) error {
	errMsg = sanitizeRunPublicString(errMsg)
	entryMode := determineAutoEntryMode("")
	if !opts.Resume && len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		entryMode = autoEntryModeMarkdownPath
	}
	jr := autoFailureResult(entryMode, opts.Resume, errMsg, errMsg, autoFailurePipeline, false, "", "")
	jr.SecurityReadinessGate = sandbox.CloneSandboxSecurityCapabilityReadinessGateDecisionPtr(gate)
	return outputAutoJSON(out, jr)
}

func outputAutoSandboxJSONErrorWithReadinessGateForCommand(cmd *cobra.Command, out io.Writer, args []string, opts autoSandboxOptions, errMsg string, gate *sandbox.SandboxSecurityCapabilityReadinessGateDecision) error {
	if err := outputAutoSandboxJSONErrorWithReadinessGate(out, args, opts, errMsg, gate); err != nil {
		return err
	}
	return exitWithCode(cmd, ExitCodeValidation, nil)
}

func autoSandboxFactoryAttemptEnv(ctx context.Context) (map[string]string, error) {
	policy, err := autoFactoryAttemptPolicyForRun(ctx)
	if err != nil {
		return nil, err
	}
	runtimeStatePolicy, err := autoFactoryRuntimeStatePolicyForRun(ctx)
	if err != nil {
		return nil, err
	}
	if policy.MaxRunAttempts == 0 && policy.MaxReviewFixAttempts == 0 && policy.MaxCIFixAttempts == 0 && runtimeStatePolicy == "" {
		return nil, nil
	}
	env := map[string]string{}
	if policy.MaxRunAttempts != 0 || policy.MaxReviewFixAttempts != 0 || policy.MaxCIFixAttempts != 0 {
		env[autoFactoryMaxRunAttemptsEnv] = strconv.Itoa(policy.MaxRunAttempts)
		env[autoFactoryMaxReviewFixAttemptsEnv] = strconv.Itoa(policy.MaxReviewFixAttempts)
		env[autoFactoryMaxCIFixAttemptsEnv] = strconv.Itoa(policy.MaxCIFixAttempts)
	}
	if runtimeStatePolicy != "" {
		env[autoFactoryRuntimeStatePolicyEnv] = runtimeStatePolicy
	}
	return env, nil
}

func autoSandboxExecutionEnv(ctx context.Context) (map[string]string, error) {
	env, err := autoSandboxFactoryAttemptEnv(ctx)
	if err != nil {
		return nil, err
	}
	if _, explicitlyConfigured := env[autoFactoryRuntimeStatePolicyEnv]; explicitlyConfigured {
		return env, nil
	}
	if env == nil {
		env = map[string]string{}
	}
	env[autoFactoryRuntimeStatePolicyEnv] = compound.RuntimeStatePolicyCheckpointHalState
	return env, nil
}

func defaultAutoSandboxExecutionID(now time.Time) string {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return fmt.Sprintf("auto-%d", now.UTC().UnixNano())
}

func autoSandboxExitValidation(cmd *cobra.Command, err error) error {
	if cmd != nil {
		return exitWithCode(cmd, ExitCodeValidation, err)
	}
	return err
}
