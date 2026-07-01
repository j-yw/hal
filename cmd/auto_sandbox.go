package cmd

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
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
}

type autoSandboxRequest struct {
	ExecutionID    string
	JSON           bool
	Args           []string
	SandboxName    string
	SandboxHostID  string
	SandboxRuntime string
	ProjectDir     string
	WorkDir        string
	RepoRemote     string
	BaseBranch     string
	RunBranch      string
	RemoteCommand  []string
	Env            map[string]string
	Flags          autoSandboxOptions
	Workspace      *sandbox.SandboxWorkspace
	WorkspacePlan  *sandboxworkspace.Plan
	Security       sandbox.SecurityEvaluationRequest
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
	OnTargetReady func(*sandbox.SandboxState) error
}

type autoSandboxDeps struct {
	defaultStore           func() (sandboxexecution.Store, error)
	newExecutionID         func(time.Time) string
	now                    func() time.Time
	planWorkspace          func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error)
	loadSandbox            func(string) (*sandbox.SandboxState, error)
	listSandboxes          func() ([]*sandbox.SandboxState, error)
	listHosts              func() ([]*sandbox.SandboxHost, error)
	resolveDefault         func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error)
	provision              func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error)
	resolveProvider        func(string) (sandbox.Provider, error)
	resolveRuntimeDriver   func(sandboxruntime.Target) (sandboxruntime.Driver, error)
	resolveWorkerRuntime   func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error)
	runProviderExecWithEnv func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, map[string]string, io.Writer) error
	runProviderScript      func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error
	engineAuthFiles        func() []factorySandboxAuthFile
	bootstrap              func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error)
	materializeWorkspace   func(context.Context, sandboxexec.PrepareContext, sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error)
	execute                func(context.Context, autoSandboxRequest, io.Writer, io.Writer, autoSandboxExecutionHooks) (autoSandboxExecutionResult, error)

	customRuntimeResolver bool
}

var defaultAutoSandboxDeps = autoSandboxDeps{
	defaultStore:   sandboxexecution.DefaultStore,
	newExecutionID: defaultAutoSandboxExecutionID,
	now:            time.Now,
	planWorkspace:  defaultRunSandboxWorkspacePlan,
	loadSandbox:    sandbox.LoadActiveInstance,
	listSandboxes:  sandbox.ListActiveInstances,
	listHosts:      sandbox.ListHosts,
	resolveDefault: sandbox.ResolveDefault,
	provision:      provisionFactorySandbox,
	resolveProvider: func(providerName string) (sandbox.Provider, error) {
		return resolveProviderWithFallback(".", providerName)
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

	req := autoSandboxRequest{
		JSON:           opts.JSON,
		Args:           append([]string(nil), args...),
		SandboxName:    strings.TrimSpace(opts.SandboxName),
		SandboxHostID:  targetFlags.HostID,
		SandboxRuntime: targetFlags.RuntimeDriver,
		Flags:          opts,
		Security:       runSandboxSecurityRequest(),
	}
	req.RemoteCommand = buildAutoSandboxRemoteCommand(req)
	return req, nil
}

func runAutoSandboxWithWriter(ctx context.Context, cmd *cobra.Command, args []string, projectDir string, opts autoSandboxOptions, out, errOut io.Writer, deps autoSandboxDeps) error {
	deps = normalizeAutoSandboxDeps(deps)
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
			return outputAutoSandboxJSONError(out, args, opts, err.Error())
		}
		return autoSandboxExitValidation(cmd, err)
	}

	startedAt := deps.now().UTC()
	req.ExecutionID = deps.newExecutionID(startedAt)
	store, storeErr := deps.defaultStore()
	if storeErr != nil {
		err := fmt.Errorf("open sandbox execution store: %w", storeErr)
		if opts.JSON {
			return outputAutoSandboxJSONError(out, args, opts, err.Error())
		}
		return err
	}

	projectDir = strings.TrimSpace(projectDir)
	if projectDir == "" {
		projectDir = "."
	}
	absProjectDir, err := filepath.Abs(projectDir)
	if err != nil {
		err := fmt.Errorf("resolve project directory: %w", err)
		if opts.JSON {
			return outputAutoSandboxJSONError(out, args, opts, err.Error())
		}
		return err
	}
	req.ProjectDir = filepath.Clean(absProjectDir)
	req.RemoteCommand = buildAutoSandboxRemoteCommand(req)
	if err := saveAutoSandboxManifest(store, req, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		if opts.JSON {
			return outputAutoSandboxJSONError(out, args, opts, err.Error())
		}
		return err
	}

	failBeforeRemote := func(cause error) error {
		finishedAt := deps.now().UTC()
		_ = saveAutoSandboxManifest(store, req, sandboxexecution.StatusFailed, startedAt, &finishedAt, nil)
		if opts.JSON {
			return outputAutoSandboxJSONError(out, args, opts, cause.Error())
		}
		return autoSandboxExitValidation(cmd, cause)
	}

	env, err := autoSandboxFactoryAttemptEnv(ctx)
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
	execResult, execErr := deps.execute(ctx, req, out, errOut, autoSandboxExecutionHooks{
		OnTargetReady: func(ready *sandbox.SandboxState) error {
			target = ready
			if target != nil && strings.TrimSpace(req.SandboxName) == "" {
				req.SandboxName = strings.TrimSpace(target.Name)
			}
			return saveAutoSandboxManifest(store, req, sandboxexecution.StatusRunning, startedAt, nil, target)
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
	}

	if isSandboxRunPhaseError(execErr) {
		_ = collectAutoSandboxRecoveryAfterCommandFailure(ctx, store, req, execResult, target)
	}
	if execErr == nil {
		if collectErr := collectAutoSandboxCoreStateArtifacts(ctx, store, req, execResult); collectErr != nil {
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

	finishedAt := deps.now().UTC()
	status := sandboxexecution.StatusSucceeded
	if execErr != nil {
		status = sandboxexecution.StatusFailed
	}
	if manifestErr := saveAutoSandboxManifest(store, req, status, startedAt, &finishedAt, target); manifestErr != nil && execErr == nil {
		execErr = manifestErr
	}
	if execErr != nil {
		if opts.JSON && !execResult.RemoteStarted {
			return outputAutoSandboxJSONError(out, args, opts, execErr.Error())
		}
		return execErr
	}
	return nil
}

func normalizeAutoSandboxDeps(deps autoSandboxDeps) autoSandboxDeps {
	customResolveDefault := deps.resolveDefault != nil
	customRuntimeResolver := deps.resolveRuntimeDriver != nil
	if deps.defaultStore == nil {
		deps.defaultStore = defaultAutoSandboxDeps.defaultStore
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
	if deps.provision == nil {
		deps.provision = defaultAutoSandboxDeps.provision
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
				provider, err := ensureProvider(prep.Target.Provider)
				if err != nil {
					return err
				}
				return deps.prepareAutoSandboxInputs(ctx, &req, provider, prep, prepOut)
			}
			provider, err := ensureProvider(prep.Target.Provider)
			if err != nil {
				return err
			}
			if err := deps.bootstrapAutoSandboxWorkspace(ctx, req, provider, prep, prepOut); err != nil {
				return err
			}
			return deps.prepareAutoSandboxInputs(ctx, &req, provider, prep, prepOut)
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
		PrepareCommand: func(_ context.Context, _ sandboxexec.PrepareContext, command *sandboxexec.CommandRequest) error {
			command.Command = append([]string(nil), req.RemoteCommand...)
			preparedCommand = append([]string(nil), command.Command...)
			return nil
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

func collectAutoSandboxCoreStateArtifacts(ctx context.Context, store sandboxexecution.Store, req autoSandboxRequest, result autoSandboxExecutionResult) error {
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
	})
	if err != nil {
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
	if _, err := sandboxexecution.CollectRecoveryArtifacts(ctx, collectionReq); err != nil {
		return fmt.Errorf("collect auto sandbox recovery artifacts: %w", err)
	}
	if _, err := sandboxexecution.CollectReportsArchiveArtifacts(ctx, sandboxexecution.ReportsArchiveCollectionRequest{
		ExecutionID:        req.ExecutionID,
		Store:              store,
		Runtime:            result.RuntimeDriver,
		Target:             result.Result.Target,
		RemoteWorkspaceDir: req.WorkDir,
	}); err != nil {
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
	if _, err := sandboxexecution.CollectRecoveryArtifactsBestEffort(ctx, sandboxexecution.RecoveryArtifactCollectionRequest{
		ExecutionID:        req.ExecutionID,
		Store:              store,
		Runtime:            result.RuntimeDriver,
		Target:             runtimeTarget,
		RemoteWorkspaceDir: req.WorkDir,
	}); err != nil {
		return fmt.Errorf("collect auto sandbox recovery artifacts after command failure: %w", err)
	}
	return nil
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
	return resolveSandboxCommandTarget(ctx, sandboxCommandTargetRequest{
		Purpose:             sandbox.SandboxLeasePurposeAuto,
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
}

func (deps autoSandboxDeps) bootstrapAutoSandboxWorkspace(ctx context.Context, req autoSandboxRequest, provider sandbox.Provider, prep sandboxexec.PrepareContext, out io.Writer) error {
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
		ID:          req.ExecutionID,
		Purpose:     sandboxexecution.PurposeAuto,
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
		if sandboxWorkerRoutingRequested(req.SandboxHostID, req.SandboxRuntime) {
			manifest.WorkerRouting = sandboxWorkerRoutingMetadataFromState(target)
		}
	}
	if manifest.Security == nil {
		manifest.Security = cloneSandboxSecurity(sandbox.EvaluateSandboxSecurity(req.Security))
	}
	preserveSandboxManifestArtifacts(store, manifest)
	return store.SaveManifest(manifest)
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
	entryMode := determineAutoEntryMode("")
	if !opts.Resume && len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		entryMode = autoEntryModeMarkdownPath
	}
	jr := autoFailureResult(entryMode, opts.Resume, errMsg, errMsg, autoFailurePipeline, false, "", "")
	return outputAutoJSON(out, jr)
}

func autoSandboxFactoryAttemptEnv(ctx context.Context) (map[string]string, error) {
	policy, err := autoFactoryAttemptPolicyForRun(ctx)
	if err != nil {
		return nil, err
	}
	if policy.MaxRunAttempts == 0 && policy.MaxReviewFixAttempts == 0 && policy.MaxCIFixAttempts == 0 {
		return nil, nil
	}
	return map[string]string{
		autoFactoryMaxRunAttemptsEnv:       strconv.Itoa(policy.MaxRunAttempts),
		autoFactoryMaxReviewFixAttemptsEnv: strconv.Itoa(policy.MaxReviewFixAttempts),
		autoFactoryMaxCIFixAttemptsEnv:     strconv.Itoa(policy.MaxCIFixAttempts),
	}, nil
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
