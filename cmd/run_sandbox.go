package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
	"github.com/spf13/cobra"
)

type runSandboxOptions struct {
	Engine                string
	EngineChanged         bool
	IterationsFlag        int
	IterationsChanged     bool
	Base                  string
	BaseChanged           bool
	Retries               int
	RetriesChanged        bool
	RetryDelay            time.Duration
	RetryDelayChanged     bool
	Timeout               time.Duration
	TimeoutChanged        bool
	DryRun                bool
	DryRunChanged         bool
	Story                 string
	StoryChanged          bool
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

type runSandboxRequest struct {
	ExecutionID               string
	JSON                      bool
	Iterations                int
	SandboxName               string
	SandboxHostID             string
	SandboxRuntime            string
	ProjectDir                string
	WorkDir                   string
	RepoRemote                string
	BaseBranch                string
	RunBranch                 string
	RemoteCommand             []string
	Flags                     runSandboxRunFlags
	SyncOut                   sandboxSyncOutOptions
	Workspace                 *sandbox.SandboxWorkspace
	WorkspacePlan             *sandboxworkspace.Plan
	Security                  sandbox.SecurityEvaluationRequest
	NetworkProxySession       *sandbox.SandboxNetworkProxySessionMetadata
	NetworkPolicyDecisionLogs []sandbox.SandboxNetworkPolicyDecisionLogRecord
}

type runSandboxExecutionResult struct {
	Result        *sandboxexec.Result
	RuntimeDriver sandboxruntime.Driver
	RemoteStarted bool
	StdoutSummary string
	StderrSummary string
}

type runSandboxExecutionHooks struct {
	OnTargetReady func(*sandbox.SandboxState) error
}

type runSandboxDeps struct {
	defaultStore           func() (sandboxexecution.Store, error)
	newExecutionID         func(time.Time) string
	now                    func() time.Time
	workingDir             func() (string, error)
	currentBranch          func(string) (string, error)
	repoRemote             func(string) (string, error)
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
	applySyncOut           sandboxSyncOutApplier
	execute                func(context.Context, runSandboxRequest, io.Writer, io.Writer, runSandboxExecutionHooks) (runSandboxExecutionResult, error)

	customRuntimeResolver bool
}

var defaultRunSandboxDeps = runSandboxDeps{
	defaultStore:        sandboxexecution.DefaultStore,
	newExecutionID:      defaultRunSandboxExecutionID,
	now:                 time.Now,
	workingDir:          os.Getwd,
	currentBranch:       compound.CurrentBranchOptionalInDir,
	repoRemote:          readGitRemoteOptionalInDir,
	planWorkspace:       defaultRunSandboxWorkspacePlan,
	loadSandbox:         sandbox.LoadActiveInstance,
	listSandboxes:       sandbox.ListActiveInstances,
	listHosts:           sandbox.ListHosts,
	resolveDefault:      sandbox.ResolveDefault,
	provision:           provisionFactorySandbox,
	persistSandboxState: sandbox.ForceWriteInstance,
	resolveProvider: func(providerName string) (sandbox.Provider, error) {
		return resolveProviderWithFallback(".", providerName)
	},
	runProviderExecWithEnv: runFactorySandboxProviderExecWithEnv,
	runProviderScript:      runFactorySandboxProviderScript,
	engineAuthFiles:        factorySandboxEngineAuthFiles,
	bootstrap:              factory.BootstrapWorkspace,
}

type runSandboxRunFlags struct {
	Engine               string
	EngineChanged        bool
	IterationsFlag       int
	IterationsChanged    bool
	IterationsPositional bool
	Base                 string
	BaseChanged          bool
	Retries              int
	RetriesChanged       bool
	RetryDelay           time.Duration
	RetryDelayChanged    bool
	Timeout              time.Duration
	TimeoutChanged       bool
	DryRun               bool
	DryRunChanged        bool
	Story                string
	StoryChanged         bool
	JSON                 bool
	JSONChanged          bool
}

func parseRunSandboxRequest(args []string, opts runSandboxOptions) (runSandboxRequest, error) {
	if len(args) > 1 {
		return runSandboxRequest{}, fmt.Errorf("accepts at most 1 arg(s), received %d", len(args))
	}

	explicitSandboxName := strings.TrimSpace(opts.SandboxName)
	if opts.SandboxNameChanged && explicitSandboxName == "" {
		return runSandboxRequest{}, fmt.Errorf("--sandbox-name must not be empty")
	}

	var positionalIterations []string
	var positionalSandboxName string
	if len(args) == 1 {
		positional := strings.TrimSpace(args[0])
		if positional == "" {
			return runSandboxRequest{}, fmt.Errorf("sandbox positional argument must not be empty")
		}
		if isRunSandboxInteger(positional) {
			positionalIterations = []string{positional}
		} else {
			positionalSandboxName = positional
		}
	}

	if positionalSandboxName != "" && opts.SandboxNameChanged {
		return runSandboxRequest{}, fmt.Errorf("sandbox name provided both positionally and via --sandbox-name")
	}

	iterations, err := parseIterations(positionalIterations, opts.IterationsFlag, opts.IterationsChanged, 10)
	if err != nil {
		return runSandboxRequest{}, err
	}
	if opts.Timeout < 0 {
		return runSandboxRequest{}, fmt.Errorf("--timeout must be greater than or equal to 0")
	}
	if opts.EngineChanged && strings.TrimSpace(opts.Engine) == "" {
		return runSandboxRequest{}, fmt.Errorf("--engine must not be empty")
	}
	targetFlags, err := parseSandboxTargetFlagValues(sandboxTargetFlagValues{
		HostID:         opts.SandboxHostID,
		HostChanged:    opts.SandboxHostChanged,
		RuntimeDriver:  opts.SandboxRuntime,
		RuntimeChanged: opts.SandboxRuntimeChanged,
	})
	if err != nil {
		return runSandboxRequest{}, err
	}
	syncOut := parseSandboxSyncOutFlagValues(sandboxSyncOutFlagValues{
		SyncOut:        opts.SandboxSyncOut,
		SyncOutChanged: opts.SandboxSyncOutChanged,
		Apply:          opts.SandboxApply,
		ApplyChanged:   opts.SandboxApplyChanged,
	})

	sandboxName := explicitSandboxName
	if positionalSandboxName != "" {
		sandboxName = positionalSandboxName
	}
	flags := runSandboxRunFlags{
		Engine:               opts.Engine,
		EngineChanged:        opts.EngineChanged,
		IterationsFlag:       opts.IterationsFlag,
		IterationsChanged:    opts.IterationsChanged,
		IterationsPositional: len(positionalIterations) > 0,
		Base:                 opts.Base,
		BaseChanged:          opts.BaseChanged,
		Retries:              opts.Retries,
		RetriesChanged:       opts.RetriesChanged,
		RetryDelay:           opts.RetryDelay,
		RetryDelayChanged:    opts.RetryDelayChanged,
		Timeout:              opts.Timeout,
		TimeoutChanged:       opts.TimeoutChanged,
		DryRun:               opts.DryRun,
		DryRunChanged:        opts.DryRunChanged,
		Story:                opts.Story,
		StoryChanged:         opts.StoryChanged,
		JSON:                 opts.JSON,
		JSONChanged:          opts.JSONChanged,
	}
	req := runSandboxRequest{
		JSON:           opts.JSON,
		Iterations:     iterations,
		SandboxName:    sandboxName,
		SandboxHostID:  targetFlags.HostID,
		SandboxRuntime: targetFlags.RuntimeDriver,
		Flags:          flags,
		SyncOut:        syncOut,
		Security:       runSandboxSecurityRequest(),
	}
	req.RemoteCommand = buildRunSandboxRemoteCommand(req)
	return req, nil
}

func runRunSandboxWithWriter(ctx context.Context, cmd *cobra.Command, args []string, opts runSandboxOptions, out, errOut io.Writer, deps runSandboxDeps) error {
	deps = normalizeRunSandboxDeps(deps)
	if ctx == nil {
		ctx = context.Background()
	}
	if out == nil {
		out = io.Discard
	}
	if errOut == nil {
		errOut = io.Discard
	}

	req, err := parseRunSandboxRequest(args, opts)
	if err != nil {
		if opts.JSON {
			return outputRunJSONError(out, err.Error())
		}
		return runSandboxExitValidation(cmd, err)
	}

	startedAt := deps.now().UTC()
	req.ExecutionID = deps.newExecutionID(startedAt)
	store, storeErr := deps.defaultStore()
	if storeErr != nil {
		if opts.JSON {
			return outputRunJSONError(out, fmt.Errorf("open sandbox execution store: %w", storeErr).Error())
		}
		return fmt.Errorf("open sandbox execution store: %w", storeErr)
	}

	projectDir, err := deps.workingDir()
	if err != nil {
		err = fmt.Errorf("resolve project directory: %w", err)
		if opts.JSON {
			return outputRunJSONError(out, err.Error())
		}
		return err
	}
	req.ProjectDir = projectDir
	securityReq, err := loadConfiguredSandboxSecurityRequest(projectDir, req.SandboxRuntime)
	if err != nil {
		err = fmt.Errorf("load sandbox security config: %w", err)
		if opts.JSON {
			return outputRunJSONError(out, err.Error())
		}
		return err
	}
	req.Security = securityReq
	if err := saveRunSandboxManifest(store, req, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		if opts.JSON {
			return outputRunJSONError(out, err.Error())
		}
		return err
	}

	failBeforeRemote := func(cause error) error {
		finishedAt := deps.now().UTC()
		_ = saveRunSandboxManifest(store, req, sandboxexecution.StatusFailed, startedAt, &finishedAt, nil)
		if opts.JSON {
			return outputRunJSONError(out, cause.Error())
		}
		return runSandboxExitValidation(cmd, cause)
	}

	if err := prepareRunSandboxRequest(ctx, &req, opts, deps); err != nil {
		return failBeforeRemote(err)
	}
	if err := saveRunSandboxManifest(store, req, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		return failBeforeRemote(err)
	}

	var target *sandbox.SandboxState
	commandOut := out
	var capturedJSON bytes.Buffer
	augmentJSON := opts.JSON && req.SyncOut.Enabled
	if augmentJSON {
		commandOut = &capturedJSON
	}
	execResult, execErr := deps.execute(ctx, req, commandOut, errOut, runSandboxExecutionHooks{
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
			return saveRunSandboxManifest(store, req, sandboxexecution.StatusRunning, startedAt, nil, target)
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
	if execErr != nil {
		if phaseErr, ok := sandboxexec.AsPhaseError(execErr); ok && phaseErr.Target != nil && target == nil {
			target = phaseErr.Target
			if strings.TrimSpace(req.SandboxName) == "" {
				req.SandboxName = strings.TrimSpace(target.Name)
			}
		}
	}

	if isSandboxRunPhaseError(execErr) {
		_ = collectRunSandboxRecoveryAfterCommandFailure(ctx, store, req, execResult, target)
	}
	if execErr == nil {
		if collectErr := collectRunSandboxCoreStateArtifacts(ctx, store, req, execResult); collectErr != nil {
			execErr = collectErr
		}
	}
	if execErr == nil {
		if collectErr := collectRunSandboxGeneratedArtifacts(ctx, store, req, execResult); collectErr != nil {
			execErr = collectErr
		}
	}
	if execErr == nil {
		if collectErr := collectRunSandboxOutputSummaryArtifacts(store, req, execResult, target); collectErr != nil {
			execErr = collectErr
		}
	}
	if execErr == nil {
		if applyErr := applyRunSandboxSyncOut(ctx, store, req, deps); applyErr != nil {
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
	if manifestErr := saveRunSandboxManifest(store, req, status, startedAt, &finishedAt, target); manifestErr != nil && execErr == nil {
		execErr = manifestErr
	}
	if augmentJSON && execResult.RemoteStarted {
		if outputErr := outputSandboxSyncOutAugmentedJSON(out, capturedJSON.Bytes(), store, req.ExecutionID); outputErr != nil {
			execErr = errors.Join(execErr, outputErr)
		}
	}
	if execErr != nil {
		if opts.JSON && !execResult.RemoteStarted {
			return outputRunJSONError(out, execErr.Error())
		}
		return execErr
	}
	return nil
}

func normalizeRunSandboxDeps(deps runSandboxDeps) runSandboxDeps {
	customDefaultStore := deps.defaultStore != nil
	customResolveDefault := deps.resolveDefault != nil
	customRuntimeResolver := deps.resolveRuntimeDriver != nil
	useDefaultWorkspacePlanner := deps.planWorkspace == nil && deps.currentBranch == nil && deps.repoRemote == nil
	if deps.defaultStore == nil {
		deps.defaultStore = defaultRunSandboxDeps.defaultStore
	}
	if deps.newExecutionID == nil {
		deps.newExecutionID = defaultRunSandboxDeps.newExecutionID
	}
	if deps.now == nil {
		deps.now = defaultRunSandboxDeps.now
	}
	if deps.workingDir == nil {
		deps.workingDir = defaultRunSandboxDeps.workingDir
	}
	if deps.currentBranch == nil {
		deps.currentBranch = defaultRunSandboxDeps.currentBranch
	}
	if deps.repoRemote == nil {
		deps.repoRemote = defaultRunSandboxDeps.repoRemote
	}
	if useDefaultWorkspacePlanner {
		deps.planWorkspace = defaultRunSandboxDeps.planWorkspace
	}
	if deps.loadSandbox == nil {
		deps.loadSandbox = defaultRunSandboxDeps.loadSandbox
	}
	if deps.resolveDefault == nil {
		deps.resolveDefault = defaultRunSandboxDeps.resolveDefault
	}
	if deps.listSandboxes == nil {
		if customResolveDefault {
			deps.listSandboxes = sandboxCommandListSandboxesFromDefault(deps.resolveDefault)
		} else {
			deps.listSandboxes = defaultRunSandboxDeps.listSandboxes
		}
	}
	if deps.listHosts == nil {
		deps.listHosts = defaultRunSandboxDeps.listHosts
	}
	if deps.listLeases == nil {
		deps.listLeases = sandboxCommandDefaultLeaseLister(deps.now, customDefaultStore)
	}
	if deps.provision == nil {
		deps.provision = defaultRunSandboxDeps.provision
	}
	if deps.acquireLease == nil {
		deps.acquireLease = sandboxCommandDefaultLeaseAcquirer(deps.now, customDefaultStore)
	}
	if deps.releaseLease == nil {
		deps.releaseLease = sandboxCommandDefaultLeaseReleaser(deps.now, customDefaultStore)
	}
	if deps.resolveProvider == nil {
		deps.resolveProvider = defaultRunSandboxDeps.resolveProvider
	}
	if deps.resolveRuntimeDriver == nil {
		deps.resolveRuntimeDriver = func(target sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return sandboxRuntimeDriverFromTarget(target, deps.resolveProvider)
		}
	}
	deps.customRuntimeResolver = customRuntimeResolver
	if deps.runProviderExecWithEnv == nil {
		deps.runProviderExecWithEnv = defaultRunSandboxDeps.runProviderExecWithEnv
	}
	if deps.runProviderScript == nil {
		deps.runProviderScript = defaultRunSandboxDeps.runProviderScript
	}
	if deps.engineAuthFiles == nil {
		deps.engineAuthFiles = defaultRunSandboxDeps.engineAuthFiles
	}
	if deps.bootstrap == nil {
		deps.bootstrap = defaultRunSandboxDeps.bootstrap
	}
	if deps.materializeWorkspace == nil {
		deps.materializeWorkspace = sandboxexec.MaterializeBundleWorkspace
	}
	if deps.execute == nil {
		deps.execute = deps.executeRunSandbox
	}
	return deps
}

func prepareRunSandboxRequest(ctx context.Context, req *runSandboxRequest, opts runSandboxOptions, deps runSandboxDeps) error {
	if deps.planWorkspace != nil {
		return prepareRunSandboxRequestWithPlan(ctx, req, opts, deps)
	}
	return prepareRunSandboxRequestLegacy(req, opts, deps)
}

func prepareRunSandboxRequestWithPlan(ctx context.Context, req *runSandboxRequest, opts runSandboxOptions, deps runSandboxDeps) error {
	plan, err := deps.planWorkspace(ctx, sandboxworkspace.Request{
		ProjectDir:      req.ProjectDir,
		WorkspaceMode:   sandbox.SandboxWorkspaceModeClone,
		PreferredBranch: strings.TrimSpace(opts.Base),
	})
	if err != nil {
		return fmt.Errorf("plan sandbox workspace: %w", err)
	}

	repoRemote := strings.TrimSpace(plan.Repository)
	if repoRemote == "" {
		return fmt.Errorf("resolve repository remote: remote.origin.url is required for sandbox execution")
	}
	branchName := strings.TrimSpace(plan.Branch)
	baseBranch := strings.TrimSpace(opts.Base)
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
			return prepareRunSandboxWorkDir(req)
		}
		return fmt.Errorf("plan sandbox workspace: unsupported clone input source %q for hal run --sandbox", inputSource)
	}
	return prepareRunSandboxWorkDir(req)
}

func prepareRunSandboxRequestLegacy(req *runSandboxRequest, opts runSandboxOptions, deps runSandboxDeps) error {
	repoRemote, err := deps.repoRemote(req.ProjectDir)
	if err != nil {
		return fmt.Errorf("resolve repository remote: %w", err)
	}
	repoRemote = strings.TrimSpace(repoRemote)
	if repoRemote == "" {
		return fmt.Errorf("resolve repository remote: remote.origin.url is required for sandbox execution")
	}
	branchName, err := deps.currentBranch(req.ProjectDir)
	if err != nil {
		return fmt.Errorf("resolve current branch: %w", err)
	}
	branchName = strings.TrimSpace(branchName)
	baseBranch := strings.TrimSpace(opts.Base)
	if baseBranch == "" {
		baseBranch = branchName
	}
	if baseBranch == "" {
		return fmt.Errorf("resolve base branch: current branch is required for sandbox execution; pass --base explicitly")
	}

	req.RepoRemote = repoRemote
	req.BaseBranch = baseBranch
	req.RunBranch = branchName
	req.Workspace = &sandbox.SandboxWorkspace{
		Mode:        sandbox.SandboxWorkspaceModeClone,
		InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
		Repo:        repoRemote,
		Branch:      branchName,
		SyncRef:     baseBranch,
	}
	return prepareRunSandboxWorkDir(req)
}

func prepareRunSandboxWorkDir(req *runSandboxRequest) error {
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

func sandboxWorkspaceMetadataFromPlan(plan sandboxworkspace.Plan, defaultInputSource, defaultSyncRef string) sandbox.SandboxWorkspace {
	workspace := sandboxworkspace.ToSandboxWorkspace(plan)
	if strings.TrimSpace(workspace.Mode) == "" {
		workspace.Mode = sandbox.SandboxWorkspaceModeClone
	}
	if strings.TrimSpace(workspace.InputSource) == "" {
		workspace.InputSource = strings.TrimSpace(defaultInputSource)
	}
	if strings.TrimSpace(workspace.SyncRef) == "" {
		workspace.SyncRef = strings.TrimSpace(defaultSyncRef)
	}
	return workspace
}

func sandboxWorkspacePlanForCommand(plan sandboxworkspace.Plan, projectDir, defaultInputSource string) sandboxworkspace.Plan {
	if strings.TrimSpace(plan.Mode) == "" {
		plan.Mode = sandbox.SandboxWorkspaceModeClone
	}
	if strings.TrimSpace(plan.ProjectDir) == "" {
		plan.ProjectDir = strings.TrimSpace(projectDir)
	}
	inputSource := strings.TrimSpace(plan.InputSource)
	if plan.RequiresBundle {
		inputSource = sandbox.SandboxWorkspaceInputSourceGitBundle
	}
	if inputSource == "" {
		inputSource = strings.TrimSpace(defaultInputSource)
	}
	plan.InputSource = inputSource
	return plan
}

func cloneSandboxWorkspacePlan(plan sandboxworkspace.Plan) *sandboxworkspace.Plan {
	clone := plan
	return &clone
}

func isGitBundleWorkspace(workspace *sandbox.SandboxWorkspace) bool {
	return workspace != nil && strings.TrimSpace(workspace.InputSource) == sandbox.SandboxWorkspaceInputSourceGitBundle
}

func defaultRunSandboxWorkspacePlan(ctx context.Context, req sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
	return sandboxworkspace.Planner{}.Plan(ctx, req)
}

func (deps runSandboxDeps) executeRunSandbox(ctx context.Context, req runSandboxRequest, out, errOut io.Writer, hooks runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
	prepOut := out
	if req.JSON {
		prepOut = errOut
	}
	var remoteStarted bool
	var provider sandbox.Provider
	var runtimeDriver sandboxruntime.Driver
	var selectedTarget *sandbox.SandboxState
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
		Purpose:     sandbox.SandboxLeasePurposeRun,
		ProjectDir:  req.ProjectDir,
		SandboxName: req.SandboxName,
		Command:     append([]string(nil), req.RemoteCommand...),
		WorkDir:     req.WorkDir,
		Security:    req.Security,
		Stdout:      out,
		Stderr:      errOut,
		SetupStdout: prepOut,
		SetupStderr: prepOut,
	}, sandboxexec.Dependencies{
		ResolveTarget: func(ctx context.Context, _ sandboxexec.TargetRequest) (*sandbox.SandboxState, error) {
			target, err := deps.resolveRunSandboxTarget(ctx, req, prepOut)
			if err == nil {
				selectedTarget = target
			}
			return target, err
		},
		ResolveDriver: func(_ context.Context, target sandboxruntime.Target) (sandboxruntime.Driver, error) {
			driver, handled, err := deps.resolveRunSandboxRuntimeDriver(req, target, selectedTarget)
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
				return err
			}
			provider, err := ensureProvider(prep.Target.Provider)
			if err != nil {
				return err
			}
			return deps.bootstrapRunSandboxWorkspace(ctx, req, provider, prep, prepOut)
		},
		PrepareAuth: func(ctx context.Context, prep sandboxexec.PrepareContext, _ *sandboxexec.CommandRequest) error {
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
		RunCommand: func(ctx context.Context, run sandboxexec.RunContext, command sandboxexec.CommandRequest) error {
			return runSandboxRuntimeExec(ctx, run, command)
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
	return runSandboxExecutionResult{
		Result:        result,
		RuntimeDriver: runtimeDriver,
		RemoteStarted: remoteStarted,
		StdoutSummary: stdoutSummary.String(),
		StderrSummary: stderrSummary.String(),
	}, err
}

func (deps runSandboxDeps) resolveRunSandboxRuntimeDriver(req runSandboxRequest, target sandboxruntime.Target, selectedTarget *sandbox.SandboxState) (sandboxruntime.Driver, bool, error) {
	if !runSandboxWorkerRuntimeRouteSelected(req, target, selectedTarget) {
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

func runSandboxWorkerRuntimeRouteSelected(req runSandboxRequest, target sandboxruntime.Target, selectedTarget *sandbox.SandboxState) bool {
	return sandboxWorkerRuntimeRouteSelected(req.SandboxHostID, req.SandboxRuntime, target, selectedTarget)
}

func collectRunSandboxCoreStateArtifacts(ctx context.Context, store sandboxexecution.Store, req runSandboxRequest, result runSandboxExecutionResult) error {
	if result.Result == nil || result.RuntimeDriver == nil {
		return nil
	}
	_, err := sandboxexecution.CollectCoreStateArtifacts(ctx, sandboxexecution.CoreStateCollectionRequest{
		ExecutionID:        req.ExecutionID,
		Store:              store,
		Runtime:            result.RuntimeDriver,
		Target:             result.Result.Target,
		Purpose:            sandboxexecution.PurposeRun,
		RemoteWorkspaceDir: req.WorkDir,
	})
	if err != nil {
		if handled, warningErr := appendSandboxArtifactCopyWarning(store, req.ExecutionID, err); handled {
			if warningErr != nil {
				return fmt.Errorf("collect run sandbox core state artifacts: %w", warningErr)
			}
			return nil
		}
		return fmt.Errorf("collect run sandbox core state artifacts: %w", err)
	}
	return nil
}

func collectRunSandboxGeneratedArtifacts(ctx context.Context, store sandboxexecution.Store, req runSandboxRequest, result runSandboxExecutionResult) error {
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
	if _, err := sandboxexecution.CollectRecoveryArtifacts(ctx, collectionReq); err != nil {
		if handled, warningErr := appendSandboxArtifactCopyWarning(store, req.ExecutionID, err); handled {
			if warningErr != nil {
				return fmt.Errorf("collect run sandbox recovery artifacts: %w", warningErr)
			}
		} else {
			return fmt.Errorf("collect run sandbox recovery artifacts: %w", err)
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
				return fmt.Errorf("collect run sandbox reports archive artifacts: %w", warningErr)
			}
			return nil
		}
		return fmt.Errorf("collect run sandbox reports archive artifacts: %w", err)
	}
	return nil
}

func collectRunSandboxRecoveryAfterCommandFailure(ctx context.Context, store sandboxexecution.Store, req runSandboxRequest, result runSandboxExecutionResult, target *sandbox.SandboxState) error {
	if result.RuntimeDriver == nil {
		return nil
	}
	runtimeTarget, ok := runSandboxRuntimeTargetForCollection(result, target)
	if !ok {
		return nil
	}
	if _, err := sandboxexecution.CollectRecoveryArtifactsBestEffort(ctx, sandboxexecution.RecoveryArtifactCollectionRequest{
		ExecutionID:        req.ExecutionID,
		Store:              store,
		Runtime:            result.RuntimeDriver,
		Target:             runtimeTarget,
		RemoteWorkspaceDir: req.WorkDir,
	}); err != nil {
		return fmt.Errorf("collect run sandbox recovery artifacts after command failure: %w", err)
	}
	return nil
}

func runSandboxRuntimeTargetForCollection(result runSandboxExecutionResult, target *sandbox.SandboxState) (sandboxruntime.Target, bool) {
	if result.Result != nil {
		return result.Result.Target, true
	}
	if target != nil {
		return sandboxRuntimeTargetFromState(target), true
	}
	return sandboxruntime.Target{}, false
}

func collectRunSandboxOutputSummaryArtifacts(store sandboxexecution.Store, req runSandboxRequest, result runSandboxExecutionResult, target *sandbox.SandboxState) error {
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
		return fmt.Errorf("collect run sandbox output summary artifacts: %w", err)
	}
	return nil
}

func isSandboxRunPhaseError(err error) bool {
	phaseErr, ok := sandboxexec.AsPhaseError(err)
	return ok && phaseErr.Phase == sandboxexec.PhaseRun
}

func appendSandboxOutputSummaryLine(summary *strings.Builder, line string) {
	if summary == nil || strings.TrimSpace(line) == "" {
		return
	}
	summary.WriteString(line)
	summary.WriteByte('\n')
}

func sanitizeSandboxOutputSummary(value string, target *sandbox.SandboxState) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	redactor := sandboxRedactor(false, nil, target)
	return sanitizeCredentialedRemoteReferences(redactor.Redact(value))
}

func (deps runSandboxDeps) resolveRunSandboxTarget(ctx context.Context, req runSandboxRequest, out io.Writer) (*sandbox.SandboxState, error) {
	if runSandboxShouldUseScheduledTarget(req) {
		return resolveSandboxCommandScheduledTarget(sandboxCommandScheduledTargetRequest{
			Purpose:        sandbox.SandboxLeasePurposeRun,
			SandboxName:    req.SandboxName,
			SandboxHostID:  req.SandboxHostID,
			SandboxRuntime: req.SandboxRuntime,
			ProjectDir:     req.ProjectDir,
			Repository:     req.RepoRemote,
			Branch:         req.RunBranch,
			RunID:          req.ExecutionID,
			Workspace:      req.Workspace,
		}, sandboxCommandScheduledTargetDeps{
			listHosts:    deps.listHosts,
			listLeases:   deps.listLeases,
			now:          deps.now,
			acquireLease: deps.acquireLease,
		})
	}

	listSandboxes := deps.listSandboxes
	if listSandboxes == nil && deps.resolveDefault != nil {
		listSandboxes = sandboxCommandListSandboxesFromDefault(deps.resolveDefault)
	}
	target, err := resolveSandboxCommandTarget(ctx, sandboxCommandTargetRequest{
		Purpose:             sandbox.SandboxLeasePurposeRun,
		SandboxName:         req.SandboxName,
		SandboxHostID:       req.SandboxHostID,
		SandboxRuntime:      req.SandboxRuntime,
		ProjectDir:          req.ProjectDir,
		Repository:          req.RepoRemote,
		Branch:              req.RunBranch,
		ProvisionRepository: req.RepoRemote,
		Out:                 out,
	}, sandboxCommandTargetDeps{
		loadSandbox:    deps.loadSandbox,
		listSandboxes:  listSandboxes,
		listHosts:      deps.listHosts,
		resolveDefault: deps.resolveDefault,
		provision:      deps.provision,
	})
	if err != nil {
		return nil, err
	}
	if !sandboxWorkerRoutingRequested(req.SandboxHostID, req.SandboxRuntime) {
		target = sandboxCommandSSHMachineCompatWorkerTarget(target)
	}
	return target, nil
}

func runSandboxShouldUseScheduledTarget(req runSandboxRequest) bool {
	return strings.TrimSpace(req.SandboxName) == "" && sandboxWorkerRoutingRequested(req.SandboxHostID, req.SandboxRuntime)
}

func runSandboxRuntimeExec(ctx context.Context, run sandboxexec.RunContext, command sandboxexec.CommandRequest) error {
	if run.Driver == nil {
		return fmt.Errorf("sandbox runtime driver is required")
	}
	_, err := run.Driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target: run.Target,
		Args:   runSandboxRemoteExecArgs(command),
		Stdout: command.Stdout,
		Stderr: command.Stderr,
		Stdin:  command.Stdin,
		Env:    command.Env,
	})
	return err
}

func (deps runSandboxDeps) bootstrapRunSandboxWorkspace(ctx context.Context, req runSandboxRequest, provider sandbox.Provider, prep sandboxexec.PrepareContext, out io.Writer) error {
	bootstrapReq := factory.BootstrapRequest{
		RepositoryURL: req.RepoRemote,
		BaseBranch:    req.BaseBranch,
		RunBranch:     req.RunBranch,
		WorkspaceDir:  req.WorkDir,
		Options: factory.BootstrapOptions{
			RefreshHal: true,
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

func runSandboxRemoteExecArgs(command sandboxexec.CommandRequest) []string {
	if strings.TrimSpace(command.WorkDir) == "" {
		return append([]string(nil), command.Command...)
	}
	return []string{"sh", "-c", "set -eu\ncd " + shellQuote(command.WorkDir) + "\nexec " + shellCommand(command.Command)}
}

func runSandboxProviderExecWithEnv(ctx context.Context, provider sandbox.Provider, info *sandbox.ConnectInfo, args []string, env map[string]string, stdout, stderr io.Writer) error {
	if provider == nil {
		return fmt.Errorf("sandbox provider is required")
	}
	script, err := factorySandboxEnvExecScript(args, env)
	if err != nil {
		return err
	}
	cmd, err := provider.Exec(info, []string{"sh", "-s"})
	if err != nil {
		return err
	}
	if cmd == nil {
		return fmt.Errorf("sandbox provider returned nil exec command")
	}
	cmd.Stdin = strings.NewReader(script)
	return runSandboxCmdContext(ctx, cmd, stdout, stderr)
}

func runSandboxCmdContext(ctx context.Context, cmd *exec.Cmd, stdout, stderr io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = stdout
	}

	mu := &sync.Mutex{}
	cmd.Stdout = &runSandboxLockedWriter{mu: mu, dst: stdout}
	cmd.Stderr = &runSandboxLockedWriter{mu: mu, dst: stderr}
	if err := cmd.Start(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return err
	}

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	select {
	case err := <-waitCh:
		return err
	case <-ctx.Done():
		if cmd.Cancel != nil {
			if err := cmd.Cancel(); err != nil && cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		} else if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return errors.Join(ctx.Err(), <-waitCh)
	}
}

type runSandboxLockedWriter struct {
	mu  *sync.Mutex
	dst io.Writer
}

func (w *runSandboxLockedWriter) Write(p []byte) (int, error) {
	if w == nil || w.dst == nil {
		return len(p), nil
	}
	if w.mu == nil {
		return w.dst.Write(p)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.dst.Write(p)
}

func saveRunSandboxManifest(store sandboxexecution.Store, req runSandboxRequest, status sandboxexecution.Status, startedAt time.Time, finishedAt *time.Time, target *sandbox.SandboxState) error {
	manifest := &sandboxexecution.Manifest{
		ID:                        req.ExecutionID,
		Purpose:                   sandboxexecution.PurposeRun,
		SandboxName:               req.SandboxName,
		ProjectDir:                req.ProjectDir,
		Command:                   append([]string(nil), req.RemoteCommand...),
		WorkDir:                   req.WorkDir,
		Status:                    status,
		StartedAt:                 startedAt,
		FinishedAt:                finishedAt,
		Workspace:                 runSandboxManifestWorkspace(req),
		Security:                  cloneSandboxSecurity(nil),
		NetworkProxySession:       sandboxManifestNetworkProxySession(req.NetworkProxySession),
		NetworkPolicyDecisionLogs: sandboxManifestNetworkPolicyDecisionLogs(req.NetworkPolicyDecisionLogs),
	}
	if target != nil {
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
	preserveSandboxManifestArtifacts(store, manifest)
	return store.SaveManifest(manifest)
}

func runSandboxManifestWorkspace(req runSandboxRequest) *sandbox.SandboxWorkspace {
	if sandboxWorkerRoutingRequested(req.SandboxHostID, req.SandboxRuntime) {
		return sandboxCommandPersistentWorkspace(req.Workspace)
	}
	return cloneSandboxWorkspace(req.Workspace)
}

func workerRootlessManifestHost(host *sandbox.SandboxHost) *sandbox.SandboxHost {
	persisted := sandboxCommandPersistentHost(host)
	if persisted == nil {
		return nil
	}
	persisted.Security = cloneSandboxSecurity(host.Security)
	return persisted
}

func preserveSandboxManifestArtifacts(store sandboxexecution.Store, manifest *sandboxexecution.Manifest) {
	if manifest == nil || strings.TrimSpace(manifest.ID) == "" {
		return
	}
	existing, err := store.LoadManifest(manifest.ID)
	if err != nil {
		return
	}
	manifest.Artifacts = append([]sandboxexecution.Artifact(nil), existing.Artifacts...)
	manifest.ArtifactMetadata = cloneSandboxArtifactMetadata(existing.ArtifactMetadata)
	manifest.SyncOut = cloneSandboxSyncOutSummary(existing.SyncOut)
	manifest.SyncOutApply = cloneSandboxSafeApplyResult(existing.SyncOutApply)
}

func cloneSandboxArtifactMetadata(metadata *sandboxexecution.ArtifactMetadata) *sandboxexecution.ArtifactMetadata {
	if metadata == nil {
		return nil
	}
	return &sandboxexecution.ArtifactMetadata{
		Collected: append([]sandboxexecution.ArtifactMetadataEntry(nil), metadata.Collected...),
		Partial:   append([]sandboxexecution.ArtifactMetadataEntry(nil), metadata.Partial...),
		Warnings:  append([]sandboxexecution.ArtifactWarning(nil), metadata.Warnings...),
	}
}

func cloneSandboxSyncOutSummary(summary *sandboxworkspace.SyncOutSummary) *sandboxworkspace.SyncOutSummary {
	if summary == nil {
		return nil
	}
	clone := *summary
	clone.CoreArtifacts = append([]sandboxworkspace.SyncOutArtifact(nil), summary.CoreArtifacts...)
	clone.Warnings = append([]sandboxworkspace.SyncOutWarning(nil), summary.Warnings...)
	clone.Recovery.Artifacts = append([]sandboxworkspace.SyncOutArtifact(nil), summary.Recovery.Artifacts...)
	clone.Apply.Reasons = append([]sandboxworkspace.SyncOutApplyEligibilityReason(nil), summary.Apply.Reasons...)
	clone.Committed.Patch = cloneSandboxSyncOutArtifact(summary.Committed.Patch)
	clone.Committed.Bundle = cloneSandboxSyncOutArtifact(summary.Committed.Bundle)
	clone.Uncommitted.Diff = cloneSandboxSyncOutArtifact(summary.Uncommitted.Diff)
	clone.Untracked.Archive = cloneSandboxSyncOutArtifact(summary.Untracked.Archive)
	clone.Untracked.List = cloneSandboxSyncOutArtifact(summary.Untracked.List)
	return &clone
}

func cloneSandboxSyncOutArtifact(artifact *sandboxworkspace.SyncOutArtifact) *sandboxworkspace.SyncOutArtifact {
	if artifact == nil {
		return nil
	}
	clone := *artifact
	if artifact.ApplyEligibility != nil {
		eligibility := *artifact.ApplyEligibility
		eligibility.Reasons = append([]sandboxworkspace.SyncOutApplyEligibilityReason(nil), artifact.ApplyEligibility.Reasons...)
		clone.ApplyEligibility = &eligibility
	}
	return &clone
}

func cloneSandboxSafeApplyResult(result *sandboxworkspace.SafeApplyResult) *sandboxworkspace.SafeApplyResult {
	if result == nil {
		return nil
	}
	clone := *result
	clone.Reasons = append([]sandboxworkspace.SyncOutApplyEligibilityReason(nil), result.Reasons...)
	clone.Warnings = append([]sandboxworkspace.SyncOutWarning(nil), result.Warnings...)
	clone.HandoffInstructions = cloneSandboxSyncOutHandoffInstructions(result.HandoffInstructions)
	return &clone
}

func cloneSandboxSyncOutHandoffInstructions(instructions []sandboxworkspace.SyncOutHandoffInstruction) []sandboxworkspace.SyncOutHandoffInstruction {
	if len(instructions) == 0 {
		return nil
	}
	clone := make([]sandboxworkspace.SyncOutHandoffInstruction, len(instructions))
	for i, instruction := range instructions {
		clone[i] = instruction
		clone[i].Artifacts = append([]sandboxworkspace.SyncOutHandoffArtifactRef(nil), instruction.Artifacts...)
	}
	return clone
}

func cloneSandboxWorkspace(workspace *sandbox.SandboxWorkspace) *sandbox.SandboxWorkspace {
	if workspace == nil {
		return nil
	}
	clone := *workspace
	return &clone
}

func cloneSandboxHost(host *sandbox.SandboxHost) *sandbox.SandboxHost {
	if host == nil {
		return nil
	}
	clone := *host
	if host.Labels != nil {
		clone.Labels = make(map[string]string, len(host.Labels))
		for key, value := range host.Labels {
			clone.Labels[key] = value
		}
	}
	clone.SupportedRuntimes = append([]string(nil), host.SupportedRuntimes...)
	clone.Security = cloneSandboxSecurity(host.Security)
	return &clone
}

func cloneSandboxRuntime(runtime *sandbox.SandboxRuntimeState) *sandbox.SandboxRuntimeState {
	if runtime == nil {
		return nil
	}
	clone := *runtime
	return &clone
}

func cloneSandboxSecurity(security *sandbox.SandboxSecurity) *sandbox.SandboxSecurity {
	if security == nil {
		return nil
	}
	clone := &sandbox.SandboxSecurity{}
	if security.Network != nil {
		network := *security.Network
		network.PolicyResult = sandbox.CloneSandboxNetworkPolicyResultPtr(security.Network.PolicyResult)
		clone.Network = &network
	}
	if security.Secrets != nil {
		secrets := *security.Secrets
		secrets.RequestedModes = append([]string(nil), security.Secrets.RequestedModes...)
		secrets.ActiveModes = append([]string(nil), security.Secrets.ActiveModes...)
		clone.Secrets = &secrets
	}
	return clone
}

func sandboxManifestNetworkProxySession(session *sandbox.SandboxNetworkProxySessionMetadata) *sandbox.SandboxNetworkProxySessionMetadata {
	if session == nil {
		return nil
	}
	sanitized := sandbox.SanitizeSandboxNetworkProxySessionMetadata(*session)
	return &sanitized
}

func sandboxManifestNetworkPolicyDecisionLogs(records []sandbox.SandboxNetworkPolicyDecisionLogRecord) []sandbox.SandboxNetworkPolicyDecisionLogRecord {
	return sandbox.SanitizeSandboxNetworkPolicyDecisionLogRecords(records)
}

func sandboxManifestSecurity(req sandbox.SecurityEvaluationRequest, target *sandbox.SandboxState) *sandbox.SandboxSecurity {
	if target != nil && selectedWorkerRootlessSandboxState(target) {
		return cloneSandboxSecurity(target.Security)
	}
	if !emptySandboxSecurityEvaluationRequest(req) {
		security := sandbox.EvaluateSandboxSecurity(req)
		mergeSandboxManifestTargetSecretModes(security, req, target)
		return cloneSandboxSecurity(security)
	}
	if target != nil {
		return cloneSandboxSecurity(target.Security)
	}
	return nil
}

func mergeSandboxManifestTargetSecretModes(security *sandbox.SandboxSecurity, req sandbox.SecurityEvaluationRequest, target *sandbox.SandboxState) {
	if security == nil || target == nil || target.Security == nil || target.Security.Secrets == nil {
		return
	}
	if len(req.ActiveSecretModes) > 0 || !legacySandboxSecretRequest(req.RequestedSecretModes) {
		return
	}
	if len(target.Security.Secrets.ActiveModes) == 0 {
		return
	}
	if security.Secrets == nil {
		security.Secrets = &sandbox.SandboxSecretSecurity{}
	}
	security.Secrets.ActiveModes = append([]string(nil), target.Security.Secrets.ActiveModes...)
}

func legacySandboxSecretRequest(modes []string) bool {
	return len(modes) == 1 && strings.TrimSpace(modes[0]) == sandbox.SandboxSecretModeHTTPProxy
}

func defaultRunSandboxExecutionID(now time.Time) string {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return fmt.Sprintf("run-%d", now.UTC().UnixNano())
}

func runSandboxExitValidation(cmd *cobra.Command, err error) error {
	if cmd != nil {
		return exitWithCode(cmd, ExitCodeValidation, err)
	}
	return err
}

func buildRunSandboxRemoteCommand(req runSandboxRequest) []string {
	flags := req.Flags
	command := []string{"hal", "run"}
	if flags.JSON {
		command = append(command, "--json")
	}
	if flags.EngineChanged {
		if engineName := strings.TrimSpace(flags.Engine); engineName != "" {
			command = append(command, "--engine", engineName)
		}
	}
	if flags.RetriesChanged {
		command = append(command, "--retries", strconv.Itoa(flags.Retries))
	}
	if flags.RetryDelayChanged {
		command = append(command, "--retry-delay", flags.RetryDelay.String())
	}
	if flags.TimeoutChanged {
		command = append(command, "--timeout", flags.Timeout.String())
	}
	if flags.DryRun {
		command = append(command, "--dry-run")
	}
	if flags.StoryChanged || strings.TrimSpace(flags.Story) != "" {
		if story := strings.TrimSpace(flags.Story); story != "" {
			command = append(command, "--story", story)
		}
	}
	if flags.BaseChanged {
		if base := strings.TrimSpace(flags.Base); base != "" {
			command = append(command, "--base", base)
		}
	}
	if flags.IterationsChanged {
		command = append(command, "--iterations", strconv.Itoa(flags.IterationsFlag))
	} else if flags.IterationsPositional {
		command = append(command, strconv.Itoa(req.Iterations))
	}
	return command
}

func runSandboxSecurityRequest() sandbox.SecurityEvaluationRequest {
	return sandbox.SecurityEvaluationRequest{
		RuntimeDriver:          sandbox.SandboxRuntimeDriverSSHMachine,
		RequestedNetworkPolicy: sandbox.SandboxNetworkPolicyDenyByDefault,
		RequestedSecretModes:   []string{sandbox.SandboxSecretModeHTTPProxy},
		CompatibilityAuthSync:  true,
	}
}

func isRunSandboxInteger(value string) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	_, err := strconv.Atoi(value)
	return err == nil
}
