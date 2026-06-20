package cmd

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
)

type factorySandboxProvisionRequest struct {
	ProjectDir string
	Name       string
	Repo       string
	Out        io.Writer
}

type factorySandboxExecutorRequest struct {
	ProjectDir   string
	SandboxName  string
	RunRecord    factory.RunRecord
	RemoteArgs   []string
	RemoteOutput io.Writer
}

type factorySandboxExecutorDeps struct {
	defaultStore    func() (factory.Store, error)
	now             func() time.Time
	resolveDefault  func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error)
	loadSandbox     func(string) (*sandbox.SandboxState, error)
	provision       func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error)
	startSandbox    func(context.Context, *sandbox.SandboxState, io.Writer) (*sandbox.SandboxState, error)
	resolveProvider func(string) (sandbox.Provider, error)
	runProviderExec func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error
	saveRun         func(factory.Store, *factory.RunRecord) error
	appendEvent     func(factory.Store, *factory.EventRecord) error
}

var defaultFactorySandboxExecutorDeps = factorySandboxExecutorDeps{
	defaultStore:   factory.DefaultStore,
	now:            time.Now,
	resolveDefault: sandbox.ResolveDefault,
	loadSandbox:    sandbox.LoadActiveInstance,
	provision:      provisionFactorySandbox,
	startSandbox:   startFactorySandbox,
	resolveProvider: func(providerName string) (sandbox.Provider, error) {
		return resolveProviderWithFallback(".", providerName)
	},
	runProviderExec: runFactorySandboxProviderExec,
	saveRun:         saveFactorySandboxRunRecord,
	appendEvent:     appendFactorySandboxTimelineEvent,
}

func normalizeFactorySandboxExecutorDeps(deps factorySandboxExecutorDeps) factorySandboxExecutorDeps {
	if deps.defaultStore == nil {
		deps.defaultStore = defaultFactorySandboxExecutorDeps.defaultStore
	}
	if deps.now == nil {
		deps.now = defaultFactorySandboxExecutorDeps.now
	}
	if deps.resolveDefault == nil {
		deps.resolveDefault = defaultFactorySandboxExecutorDeps.resolveDefault
	}
	if deps.loadSandbox == nil {
		deps.loadSandbox = defaultFactorySandboxExecutorDeps.loadSandbox
	}
	if deps.provision == nil {
		deps.provision = defaultFactorySandboxExecutorDeps.provision
	}
	if deps.startSandbox == nil {
		deps.startSandbox = defaultFactorySandboxExecutorDeps.startSandbox
	}
	if deps.resolveProvider == nil {
		deps.resolveProvider = defaultFactorySandboxExecutorDeps.resolveProvider
	}
	if deps.runProviderExec == nil {
		deps.runProviderExec = defaultFactorySandboxExecutorDeps.runProviderExec
	}
	if deps.saveRun == nil {
		deps.saveRun = defaultFactorySandboxExecutorDeps.saveRun
	}
	if deps.appendEvent == nil {
		deps.appendEvent = defaultFactorySandboxExecutorDeps.appendEvent
	}
	return deps
}

func runFactorySandboxExecutorWithDeps(ctx context.Context, req factorySandboxExecutorRequest, deps factorySandboxExecutorDeps) error {
	deps = normalizeFactorySandboxExecutorDeps(deps)
	if ctx == nil {
		ctx = context.Background()
	}

	store, err := deps.defaultStore()
	if err != nil {
		return fmt.Errorf("open factory store: %w", err)
	}

	record := req.RunRecord
	record.ExecutorMode = factory.ExecutorModeSandbox
	record.UpdatedAt = deps.now().UTC()
	if err := deps.saveRun(store, &record); err != nil {
		return fmt.Errorf("save sandbox factory run: %w", err)
	}

	var target *sandbox.SandboxState
	if name := strings.TrimSpace(req.SandboxName); name != "" {
		target, err = deps.loadSandbox(name)
	} else {
		target, _, err = deps.resolveDefault(factoryRunningSandboxFilter)
	}
	if err != nil {
		target, err = deps.provision(ctx, factorySandboxProvisionRequest{
			ProjectDir: req.ProjectDir,
			Name:       req.SandboxName,
			Repo:       record.RepoRemote,
			Out:        req.RemoteOutput,
		})
		if err != nil {
			return fmt.Errorf("provision factory sandbox: %w", err)
		}
	}
	if target == nil {
		return fmt.Errorf("factory sandbox target is required")
	}

	if target.Status != sandbox.StatusRunning {
		target, err = deps.startSandbox(ctx, target, req.RemoteOutput)
		if err != nil {
			return fmt.Errorf("start factory sandbox %q: %w", target.Name, err)
		}
	}

	provider, err := deps.resolveProvider(target.Provider)
	if err != nil {
		return fmt.Errorf("resolve sandbox provider %q: %w", target.Provider, err)
	}
	if err := deps.runProviderExec(ctx, provider, sandbox.ConnectInfoFromState(target), req.RemoteArgs, req.RemoteOutput); err != nil {
		return fmt.Errorf("execute factory sandbox command: %w", err)
	}

	return deps.appendEvent(store, &factory.EventRecord{
		RunID:     record.RunID,
		EventType: factory.EventTypeStepStarted,
		Timestamp: deps.now().UTC(),
		Summary:   "Sandbox factory executor initialized",
		Metadata: map[string]any{
			"executorMode": factory.ExecutorModeSandbox,
			"sandboxName":  target.Name,
			"provider":     target.Provider,
		},
	})
}

func factoryRunningSandboxFilter(instance *sandbox.SandboxState) bool {
	return instance != nil && instance.Status == sandbox.StatusRunning
}

func provisionFactorySandbox(ctx context.Context, req factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
	name := req.Name
	if name == "" {
		name = sandbox.SandboxNameFromBranch(req.Repo)
	}
	if err := runSandboxCreate(req.ProjectDir, name, 1, false, false, "", req.Repo, nil, autoShutdownOpts{}, req.Out, nil); err != nil {
		return nil, err
	}
	return sandbox.LoadActiveInstance(name)
}

func startFactorySandbox(ctx context.Context, instance *sandbox.SandboxState, out io.Writer) (*sandbox.SandboxState, error) {
	if instance == nil {
		return nil, fmt.Errorf("sandbox instance is required")
	}
	provider, err := resolveProviderFromState(".", instance)
	if err != nil {
		return nil, err
	}
	result, err := provider.Start(ctx, sandbox.ConnectInfoFromState(instance), out)
	if err != nil {
		return nil, err
	}
	updated := *instance
	updated.Status = sandbox.StatusRunning
	if result != nil {
		if result.Status != "" {
			updated.Status = result.Status
		}
		if result.IP != "" {
			updated.IP = result.IP
		}
	}
	if err := sandbox.ForceWriteInstance(&updated); err != nil {
		return nil, err
	}
	return &updated, nil
}

func runFactorySandboxProviderExec(ctx context.Context, provider sandbox.Provider, info *sandbox.ConnectInfo, args []string, out io.Writer) error {
	if provider == nil {
		return fmt.Errorf("sandbox provider is required")
	}
	cmd, err := provider.Exec(info, args)
	if err != nil {
		return err
	}
	return sandbox.RunCmd(cmd, out)
}

func saveFactorySandboxRunRecord(store factory.Store, record *factory.RunRecord) error {
	return store.SaveRun(record)
}

func appendFactorySandboxTimelineEvent(store factory.Store, event *factory.EventRecord) error {
	return store.AppendEvent(event)
}
