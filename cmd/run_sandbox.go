package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
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
	Engine             string
	EngineChanged      bool
	IterationsFlag     int
	IterationsChanged  bool
	Base               string
	BaseChanged        bool
	Retries            int
	RetriesChanged     bool
	RetryDelay         time.Duration
	RetryDelayChanged  bool
	Timeout            time.Duration
	TimeoutChanged     bool
	DryRun             bool
	DryRunChanged      bool
	Story              string
	StoryChanged       bool
	JSON               bool
	JSONChanged        bool
	SandboxName        string
	SandboxNameChanged bool
}

type runSandboxRequest struct {
	ExecutionID   string
	JSON          bool
	Iterations    int
	SandboxName   string
	ProjectDir    string
	WorkDir       string
	RepoRemote    string
	BaseBranch    string
	RunBranch     string
	RemoteCommand []string
	Flags         runSandboxRunFlags
	Workspace     *sandbox.SandboxWorkspace
	WorkspacePlan *sandboxworkspace.Plan
	Security      sandbox.SecurityEvaluationRequest
}

type runSandboxExecutionResult struct {
	Result        *sandboxexec.Result
	RuntimeDriver sandboxruntime.Driver
	RemoteStarted bool
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
	resolveDefault         func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error)
	provision              func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error)
	startSandbox           func(context.Context, *sandbox.SandboxState, io.Writer) (*sandbox.SandboxState, error)
	resolveProvider        func(string) (sandbox.Provider, error)
	resolveRuntimeDriver   func(string) (sandboxruntime.Driver, error)
	runProviderExecWithEnv func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, map[string]string, io.Writer) error
	runProviderScript      func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error
	engineAuthFiles        func() []factorySandboxAuthFile
	bootstrap              func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error)
	materializeWorkspace   func(context.Context, sandboxexec.PrepareContext, sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error)
	execute                func(context.Context, runSandboxRequest, io.Writer, io.Writer, runSandboxExecutionHooks) (runSandboxExecutionResult, error)
}

var defaultRunSandboxDeps = runSandboxDeps{
	defaultStore:   sandboxexecution.DefaultStore,
	newExecutionID: defaultRunSandboxExecutionID,
	now:            time.Now,
	workingDir:     os.Getwd,
	currentBranch:  compound.CurrentBranchOptionalInDir,
	repoRemote:     readGitRemoteOptionalInDir,
	planWorkspace:  defaultRunSandboxWorkspacePlan,
	loadSandbox:    sandbox.LoadActiveInstance,
	resolveDefault: sandbox.ResolveDefault,
	provision:      provisionFactorySandbox,
	startSandbox:   startFactorySandbox,
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
		JSON:        opts.JSON,
		Iterations:  iterations,
		SandboxName: sandboxName,
		Flags:       flags,
		Security:    runSandboxSecurityRequest(),
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
	execResult, execErr := deps.execute(ctx, req, out, errOut, runSandboxExecutionHooks{
		OnTargetReady: func(ready *sandbox.SandboxState) error {
			target = ready
			if target != nil && strings.TrimSpace(req.SandboxName) == "" {
				req.SandboxName = strings.TrimSpace(target.Name)
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

	if execErr == nil {
		if collectErr := collectRunSandboxCoreStateArtifacts(ctx, store, req, execResult); collectErr != nil {
			execErr = collectErr
		}
	}

	finishedAt := deps.now().UTC()
	status := sandboxexecution.StatusSucceeded
	if execErr != nil {
		status = sandboxexecution.StatusFailed
	}
	if manifestErr := saveRunSandboxManifest(store, req, status, startedAt, &finishedAt, target); manifestErr != nil && execErr == nil {
		execErr = manifestErr
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
	if deps.provision == nil {
		deps.provision = defaultRunSandboxDeps.provision
	}
	if deps.startSandbox == nil {
		deps.startSandbox = defaultRunSandboxDeps.startSandbox
	}
	if deps.resolveProvider == nil {
		deps.resolveProvider = defaultRunSandboxDeps.resolveProvider
	}
	if deps.resolveRuntimeDriver == nil {
		deps.resolveRuntimeDriver = func(providerName string) (sandboxruntime.Driver, error) {
			provider, err := deps.resolveProvider(providerName)
			if err != nil {
				return nil, err
			}
			return sandboxRuntimeDriverFromProvider(provider), nil
		}
	}
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
	}, sandboxexec.Dependencies{
		ResolveTarget: func(ctx context.Context, _ sandboxexec.TargetRequest) (*sandbox.SandboxState, error) {
			return deps.resolveRunSandboxTarget(ctx, req, prepOut)
		},
		StartTarget: func(ctx context.Context, target *sandbox.SandboxState, _, _ io.Writer) (*sandbox.SandboxState, error) {
			return deps.startSandbox(ctx, target, prepOut)
		},
		ResolveDriver: func(_ context.Context, target sandboxruntime.Target) (sandboxruntime.Driver, error) {
			driver, err := deps.resolveRuntimeDriver(target.Provider)
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
			return nil
		},
	})
	return runSandboxExecutionResult{Result: result, RuntimeDriver: runtimeDriver, RemoteStarted: remoteStarted}, err
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
		return fmt.Errorf("collect run sandbox core state artifacts: %w", err)
	}
	return nil
}

func (deps runSandboxDeps) resolveRunSandboxTarget(ctx context.Context, req runSandboxRequest, out io.Writer) (*sandbox.SandboxState, error) {
	if name := strings.TrimSpace(req.SandboxName); name != "" {
		target, err := deps.loadSandbox(name)
		if err == nil {
			return target, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("load sandbox %q: %w", name, err)
		}
		return deps.provision(ctx, factorySandboxProvisionRequest{
			ProjectDir: req.ProjectDir,
			Name:       name,
			BranchName: req.RunBranch,
			Repo:       req.RepoRemote,
			Out:        out,
		})
	}
	target, _, err := deps.resolveDefault(factoryRunningSandboxFilter)
	if err == nil {
		return target, nil
	}
	if !isFactorySandboxProvisionableResolutionError(err) {
		return nil, err
	}
	name := sandbox.SandboxNameFromBranch(req.RunBranch)
	return deps.provision(ctx, factorySandboxProvisionRequest{
		ProjectDir: req.ProjectDir,
		Name:       name,
		BranchName: req.RunBranch,
		Repo:       req.RepoRemote,
		Out:        out,
	})
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
		ID:          req.ExecutionID,
		Purpose:     sandboxexecution.PurposeRun,
		SandboxName: req.SandboxName,
		ProjectDir:  req.ProjectDir,
		Command:     append([]string(nil), req.RemoteCommand...),
		WorkDir:     req.WorkDir,
		Status:      status,
		StartedAt:   startedAt,
		FinishedAt:  finishedAt,
		Workspace:   cloneSandboxWorkspace(req.Workspace),
		Security:    cloneSandboxSecurity(nil),
	}
	if target != nil {
		if strings.TrimSpace(manifest.SandboxName) == "" {
			manifest.SandboxName = strings.TrimSpace(target.Name)
		}
		manifest.Host = cloneSandboxHost(target.Host)
		manifest.Runtime = cloneSandboxRuntime(target.Runtime)
		manifest.Security = cloneSandboxSecurity(target.Security)
	}
	if manifest.Security == nil {
		manifest.Security = cloneSandboxSecurity(sandbox.EvaluateSandboxSecurity(req.Security))
	}
	preserveRunSandboxManifestArtifacts(store, manifest)
	return store.SaveManifest(manifest)
}

func preserveRunSandboxManifestArtifacts(store sandboxexecution.Store, manifest *sandboxexecution.Manifest) {
	if manifest == nil || strings.TrimSpace(manifest.ID) == "" {
		return
	}
	existing, err := store.LoadManifest(manifest.ID)
	if err != nil {
		return
	}
	manifest.Artifacts = append([]sandboxexecution.Artifact(nil), existing.Artifacts...)
	manifest.ArtifactMetadata = cloneSandboxArtifactMetadata(existing.ArtifactMetadata)
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
