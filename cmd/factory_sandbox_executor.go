package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
)

type factorySandboxProvisionRequest struct {
	ProjectDir string
	Name       string
	BranchName string
	Repo       string
	Out        io.Writer
}

type factorySandboxExecutorRequest struct {
	ProjectDir   string
	SandboxName  string
	RunRecord    factory.RunRecord
	RemoteAuto   factoryRunAutoRequest
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
		if err != nil {
			record.SandboxName, record.Sandbox = factorySandboxMetadataFromName(name)
			target, err = deps.provision(ctx, factorySandboxProvisionRequest{
				ProjectDir: req.ProjectDir,
				Name:       name,
				BranchName: record.BranchName,
				Repo:       record.RepoRemote,
				Out:        req.RemoteOutput,
			})
			if err != nil {
				_ = recordFactorySandboxFailure(store, deps, &record, nil, "provision", err)
				return fmt.Errorf("provision factory sandbox: %w", err)
			}
		}
	} else {
		target, _, err = deps.resolveDefault(factoryRunningSandboxFilter)
		if err != nil {
			if !isFactorySandboxProvisionableResolutionError(err) {
				return err
			}
			name := factorySandboxProvisionName(record)
			record.SandboxName, record.Sandbox = factorySandboxMetadataFromName(name)
			target, err = deps.provision(ctx, factorySandboxProvisionRequest{
				ProjectDir: req.ProjectDir,
				Name:       name,
				BranchName: record.BranchName,
				Repo:       record.RepoRemote,
				Out:        req.RemoteOutput,
			})
			if err != nil {
				_ = recordFactorySandboxFailure(store, deps, &record, nil, "provision", err)
				return fmt.Errorf("provision factory sandbox: %w", err)
			}
		}
	}
	if target == nil {
		return fmt.Errorf("factory sandbox target is required")
	}

	if target.Status != sandbox.StatusRunning {
		startedTarget, err := deps.startSandbox(ctx, target, req.RemoteOutput)
		if err != nil {
			_ = recordFactorySandboxFailure(store, deps, &record, target, "start", err)
			return fmt.Errorf("start factory sandbox %q: %w", target.Name, err)
		}
		target = startedTarget
	}

	record.SandboxName, record.Sandbox = factorySandboxMetadataFromState(target)
	record.UpdatedAt = deps.now().UTC()
	if err := deps.saveRun(store, &record); err != nil {
		return fmt.Errorf("record factory sandbox metadata: %w", err)
	}

	remoteOutput := newFactorySandboxTimelineWriter(store, deps, &record, target, req.RemoteOutput)

	remoteArgs := factorySandboxRemoteAutoArgs(req.RemoteAuto)
	provider, err := deps.resolveProvider(target.Provider)
	if err != nil {
		return fmt.Errorf("resolve sandbox provider %q: %w", target.Provider, err)
	}
	runErr := deps.runProviderExec(ctx, provider, sandbox.ConnectInfoFromState(target), remoteArgs, remoteOutput)
	flushErr := remoteOutput.Flush()
	if runErr != nil {
		if flushErr != nil {
			runErr = errors.Join(runErr, fmt.Errorf("record remote sandbox output: %w", flushErr))
		}
		return fmt.Errorf("execute factory sandbox command: %w", runErr)
	}
	if flushErr != nil {
		return fmt.Errorf("record remote sandbox output: %w", flushErr)
	}

	return deps.appendEvent(store, &factory.EventRecord{
		Sequence:  remoteOutput.NextSequence(),
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

type factorySandboxTimelineWriter struct {
	mu           sync.Mutex
	dst          io.Writer
	store        factory.Store
	deps         factorySandboxExecutorDeps
	runID        string
	sandboxName  string
	provider     string
	redact       func(string) string
	pending      string
	nextSequence int64
}

func newFactorySandboxTimelineWriter(store factory.Store, deps factorySandboxExecutorDeps, record *factory.RunRecord, target *sandbox.SandboxState, dst io.Writer) *factorySandboxTimelineWriter {
	if dst == nil {
		dst = io.Discard
	}
	runID := ""
	if record != nil {
		runID = record.RunID
	}
	sandboxName := ""
	provider := ""
	if target != nil {
		sandboxName = target.Name
		provider = target.Provider
	}
	events, err := store.LoadEvents(runID)
	nextSequence := int64(1)
	if err == nil {
		nextSequence = nextFactoryRunEventSequence(events)
	}
	redactor := sandboxRedactor(false, nil, target)
	return &factorySandboxTimelineWriter{
		dst:          dst,
		store:        store,
		deps:         deps,
		runID:        runID,
		sandboxName:  sandboxName,
		provider:     provider,
		redact:       redactor.Redact,
		nextSequence: nextSequence,
	}
}

func (w *factorySandboxTimelineWriter) Write(p []byte) (int, error) {
	if w == nil {
		return len(p), nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.dst != nil {
		if _, err := w.dst.Write(p); err != nil {
			return 0, err
		}
	}
	w.pending += string(p)
	if err := w.flushCompleteLinesLocked(); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *factorySandboxTimelineWriter) Flush() error {
	if w == nil {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.flushCompleteLinesLocked(); err != nil {
		return err
	}
	line := strings.TrimSpace(w.pending)
	w.pending = ""
	if line == "" {
		return nil
	}
	return w.appendLineLocked(line)
}

func (w *factorySandboxTimelineWriter) NextSequence() int64 {
	if w == nil {
		return 1
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	return w.nextSequence
}

func (w *factorySandboxTimelineWriter) flushCompleteLinesLocked() error {
	for {
		idx := strings.IndexByte(w.pending, '\n')
		if idx < 0 {
			return nil
		}
		line := strings.TrimSpace(w.pending[:idx])
		w.pending = w.pending[idx+1:]
		if line == "" {
			continue
		}
		if err := w.appendLineLocked(line); err != nil {
			return err
		}
	}
}

func (w *factorySandboxTimelineWriter) appendLineLocked(line string) error {
	if strings.TrimSpace(w.runID) == "" {
		return nil
	}
	if w.redact != nil {
		line = w.redact(line)
	}
	event := factory.EventRecord{
		Sequence:  w.nextSequence,
		RunID:     w.runID,
		EventType: factory.EventTypeCommandOutputSummary,
		Timestamp: w.deps.now().UTC(),
		Message:   line,
		Summary:   "Remote sandbox output",
		Metadata: map[string]any{
			"source":      "remote_sandbox",
			"stream":      "remote",
			"sandboxName": w.sandboxName,
			"provider":    w.provider,
		},
	}
	if err := w.deps.appendEvent(w.store, &event); err != nil {
		return err
	}
	w.nextSequence++
	return nil
}

func factorySandboxRemoteAutoArgs(req factoryRunAutoRequest) []string {
	args := []string{"hal", "auto"}
	for _, arg := range req.Args {
		if trimmed := strings.TrimSpace(arg); trimmed != "" {
			args = append(args, trimmed)
		}
	}
	if reportPath := strings.TrimSpace(req.ReportPath); reportPath != "" {
		args = append(args, "--report", reportPath)
	}
	if baseBranch := strings.TrimSpace(req.BaseBranch); baseBranch != "" {
		args = append(args, "--base", baseBranch)
	}
	return args
}

func isFactorySandboxProvisionableResolutionError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return msg == "no sandboxes found" || msg == "no running sandboxes"
}

func factorySandboxProvisionName(record factory.RunRecord) string {
	if name := strings.TrimSpace(record.SandboxName); name != "" {
		return name
	}
	return sandbox.SandboxNameFromBranch(record.BranchName)
}

func recordFactorySandboxFailure(store factory.Store, deps factorySandboxExecutorDeps, record *factory.RunRecord, target *sandbox.SandboxState, step string, failureErr error) error {
	if record == nil {
		return nil
	}
	failedAt := deps.now().UTC()
	if target != nil {
		record.SandboxName, record.Sandbox = factorySandboxMetadataFromState(target)
	} else if strings.TrimSpace(record.SandboxName) == "" && record.Sandbox == nil {
		record.SandboxName, record.Sandbox = factorySandboxMetadataFromName("")
	}
	record.Status = factory.RunStatusFailed
	record.CurrentStep = step
	record.UpdatedAt = failedAt
	record.FinishedAt = &failedAt
	failure := factory.FailureSummary{
		Step:             step,
		Category:         factory.FailureCategoryPipeline,
		Message:          failureErr.Error(),
		Recoverable:      true,
		SuggestedCommand: factoryRunInspectCommand(record.RunID),
	}
	record.Failure = &failure
	if err := deps.saveRun(store, record); err != nil {
		return err
	}
	return deps.appendEvent(store, &factory.EventRecord{
		RunID:     record.RunID,
		EventType: factory.EventTypeFailureClassification,
		Timestamp: failedAt,
		Summary:   "Sandbox factory executor failed",
		Metadata: map[string]any{
			"step":        step,
			"category":    failure.Category,
			"recoverable": failure.Recoverable,
		},
	})
}

func factorySandboxMetadataFromState(instance *sandbox.SandboxState) (string, *factory.SandboxMetadata) {
	if instance == nil {
		return "", nil
	}

	connection := factorySandboxConnectionMetadataFromState(instance)
	metadata := &factory.SandboxMetadata{
		Name:           instance.Name,
		Provider:       instance.Provider,
		Status:         instance.Status,
		Connection:     connection,
		SSHCommand:     fmt.Sprintf("hal sandbox ssh %s", instance.Name),
		CleanupCommand: fmt.Sprintf("hal sandbox delete %s", instance.Name),
		Handoff:        fmt.Sprintf("Inspect sandbox with `hal sandbox ssh %s`.", instance.Name),
	}
	return instance.Name, metadata
}

func factorySandboxMetadataFromName(name string) (string, *factory.SandboxMetadata) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil
	}
	return name, &factory.SandboxMetadata{
		Name:           name,
		Status:         sandbox.StatusUnknown,
		SSHCommand:     fmt.Sprintf("hal sandbox ssh %s", name),
		CleanupCommand: fmt.Sprintf("hal sandbox delete %s", name),
		Handoff:        fmt.Sprintf("Inspect sandbox with `hal sandbox ssh %s`.", name),
	}
}

func factorySandboxConnectionMetadataFromState(instance *sandbox.SandboxState) *factory.SandboxConnectionMetadata {
	if instance == nil {
		return nil
	}

	connection := &factory.SandboxConnectionMetadata{
		Address:           instance.IP,
		PublicIP:          instance.IP,
		TailscaleIP:       instance.TailscaleIP,
		TailscaleHostname: instance.TailscaleHostname,
		TailscaleLockdown: instance.TailscaleLockdown,
	}
	if connection.Address == "" &&
		connection.PublicIP == "" &&
		connection.TailscaleIP == "" &&
		connection.TailscaleHostname == "" &&
		!connection.TailscaleLockdown {
		return nil
	}
	return connection
}

func factoryRunningSandboxFilter(instance *sandbox.SandboxState) bool {
	return instance != nil && instance.Status == sandbox.StatusRunning
}

func provisionFactorySandbox(ctx context.Context, req factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
	name := req.Name
	if name == "" {
		name = sandbox.SandboxNameFromBranch(req.BranchName)
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
