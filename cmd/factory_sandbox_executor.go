package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
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

type factorySandboxCleanupRequest struct {
	Target   *sandbox.SandboxState
	Provider sandbox.Provider
	Out      io.Writer
}

type factorySandboxExecutorRequest struct {
	ProjectDir    string
	SandboxName   string
	RunRecord     factory.RunRecord
	RemoteAuto    factoryRunAutoRequest
	RemoteOutput  io.Writer
	BeforeCleanup func(context.Context, factory.RunRecord) error
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
	bootstrap       func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error)
	cleanupSandbox  func(context.Context, factorySandboxCleanupRequest) error
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
	bootstrap:       factory.BootstrapWorkspace,
	cleanupSandbox:  cleanupFactorySandbox,
	saveRun:         saveFactorySandboxRunRecord,
	appendEvent:     appendFactorySandboxTimelineEvent,
}

var errFactorySandboxWorkspaceRequired = errors.New("sandbox workspace directory is required; configure remote.origin.url or run from a /workspace/<repo> checkout")

const factorySandboxCopyInputChunkEncodedBytes = 32 * 1024

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
	if deps.bootstrap == nil {
		deps.bootstrap = defaultFactorySandboxExecutorDeps.bootstrap
	}
	if deps.cleanupSandbox == nil {
		deps.cleanupSandbox = defaultFactorySandboxExecutorDeps.cleanupSandbox
	}
	if deps.saveRun == nil {
		deps.saveRun = defaultFactorySandboxExecutorDeps.saveRun
	}
	if deps.appendEvent == nil {
		deps.appendEvent = defaultFactorySandboxExecutorDeps.appendEvent
	}
	return deps
}

func runFactorySandboxExecutorWithDeps(ctx context.Context, req factorySandboxExecutorRequest, deps factorySandboxExecutorDeps) (returnErr error) {
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

	if factorySandboxRemoteWorkspaceDir(record) == "" {
		_ = recordFactorySandboxFailure(store, deps, &record, nil, "prepare_inputs", errFactorySandboxWorkspaceRequired)
		return factorySandboxRecordedError("prepare factory sandbox inputs", nil, errFactorySandboxWorkspaceRequired)
	}

	var target *sandbox.SandboxState
	if name := strings.TrimSpace(req.SandboxName); name != "" {
		target, err = deps.loadSandbox(name)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("load factory sandbox %q: %w", name, err)
			}
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
				return factorySandboxRecordedError("provision factory sandbox", nil, err)
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
			target, err = deps.loadSandbox(name)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					return fmt.Errorf("load factory sandbox %q: %w", name, err)
				}
				target, err = deps.provision(ctx, factorySandboxProvisionRequest{
					ProjectDir: req.ProjectDir,
					Name:       name,
					BranchName: record.BranchName,
					Repo:       record.RepoRemote,
					Out:        req.RemoteOutput,
				})
				if err != nil {
					_ = recordFactorySandboxFailure(store, deps, &record, nil, "provision", err)
					return factorySandboxRecordedError("provision factory sandbox", nil, err)
				}
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
			startErr := factorySandboxRecordedError(fmt.Sprintf("start factory sandbox %q", target.Name), target, err)
			if cleanupErr := cleanupFactorySandboxAfterFailedStart(ctx, deps, req, record, target); cleanupErr != nil {
				sanitizedCleanupErr := fmt.Errorf("%s", factorySandboxSanitizedError(target, fmt.Errorf("cleanup factory sandbox: %w", cleanupErr)))
				return errors.Join(startErr, sanitizedCleanupErr)
			}
			return startErr
		}
		target = startedTarget
	}

	record.SandboxName, record.Sandbox = factorySandboxMetadataFromState(target)
	record.UpdatedAt = deps.now().UTC()
	if err := deps.saveRun(store, &record); err != nil {
		return fmt.Errorf("record factory sandbox metadata: %w", err)
	}

	remoteOutput := newFactorySandboxTimelineWriter(store, deps, &record, target, req.RemoteOutput)
	provider, err := deps.resolveProvider(target.Provider)
	if err != nil {
		_ = recordFactorySandboxFailure(store, deps, &record, target, "resolve_provider", err)
		return factorySandboxRecordedError(fmt.Sprintf("resolve sandbox provider %q", target.Provider), target, err)
	}
	cleanupSucceeded := false
	defer func() {
		if cleanupErr := cleanupFactorySandboxAfterRun(ctx, deps, req, record, target, provider, req.RemoteOutput, factorySandboxCleanupBehavior(record), cleanupSucceeded); cleanupErr != nil {
			sanitizedCleanupErr := fmt.Errorf("%s", factorySandboxSanitizedError(target, fmt.Errorf("cleanup factory sandbox: %w", cleanupErr)))
			if returnErr != nil {
				returnErr = errors.Join(returnErr, sanitizedCleanupErr)
				return
			}
			returnErr = sanitizedCleanupErr
		}
	}()

	if bootstrapReq, ok := factorySandboxBootstrapRequest(record); ok {
		bootstrapResult, bootstrapErr := deps.bootstrap(ctx, bootstrapReq, factory.BootstrapDeps{
			Executor: &factorySandboxBootstrapExecutor{
				provider:        provider,
				connectInfo:     sandbox.ConnectInfoFromState(target),
				runProviderExec: deps.runProviderExec,
				// Bootstrap timelines are persisted from sanitized BootstrapResult
				// events; stream raw command output only to the caller-facing writer.
				out: req.RemoteOutput,
			},
			Now: deps.now,
		})
		if appendErr := appendFactorySandboxBootstrapTimeline(store, deps, &record, target, bootstrapResult); appendErr != nil {
			return fmt.Errorf("record sandbox bootstrap timeline: %w", appendErr)
		}
		if syncErr := remoteOutput.SyncNextSequence(); syncErr != nil {
			return fmt.Errorf("sync sandbox timeline sequence: %w", syncErr)
		}
		if bootstrapErr != nil {
			_ = recordFactorySandboxFailure(store, deps, &record, target, "bootstrap", bootstrapErr)
			return factorySandboxRecordedError("bootstrap factory sandbox workspace", target, bootstrapErr)
		}
	}

	remoteAuto, err := factorySandboxPrepareRemoteInputs(ctx, req, provider, target, remoteOutput, deps)
	if err != nil {
		_ = recordFactorySandboxFailure(store, deps, &record, target, "prepare_inputs", err)
		return factorySandboxRecordedError("prepare factory sandbox inputs", target, err)
	}

	remoteArgs := factorySandboxRemoteCommandArgs(record, remoteAuto)
	if err := remoteOutput.appendExecutorEvent(factory.EventTypeStepStarted, "Remote sandbox execution started", map[string]any{
		"command": strings.Join(remoteArgs, " "),
		"status":  factory.RunStatusRunning,
	}); err != nil {
		return fmt.Errorf("record remote sandbox start: %w", err)
	}
	runErr := deps.runProviderExec(ctx, provider, sandbox.ConnectInfoFromState(target), remoteArgs, remoteOutput)
	flushErr := remoteOutput.Flush()
	if runErr != nil {
		if flushErr != nil {
			runErr = errors.Join(runErr, fmt.Errorf("record remote sandbox output: %w", flushErr))
		}
		sanitizedErr := factorySandboxSanitizedError(target, runErr)
		_ = recordFactorySandboxFailure(store, deps, &record, target, "run", fmt.Errorf("%s", sanitizedErr))
		return fmt.Errorf("execute factory sandbox command: %s", sanitizedErr)
	}
	if flushErr != nil {
		return fmt.Errorf("record remote sandbox output: %w", flushErr)
	}
	if err := remoteOutput.appendExecutorEvent(factory.EventTypeStepEnded, "Remote sandbox execution completed", map[string]any{
		"status": factory.RunStatusSucceeded,
	}); err != nil {
		return err
	}
	cleanupSucceeded = true
	return nil
}

func factorySandboxCleanupBehavior(record factory.RunRecord) string {
	if record.Policy == nil {
		return factory.CleanupBehaviorPreserve
	}
	switch strings.TrimSpace(record.Policy.CleanupBehavior) {
	case factory.CleanupBehaviorOnSuccess:
		return factory.CleanupBehaviorOnSuccess
	case factory.CleanupBehaviorAlways:
		return factory.CleanupBehaviorAlways
	default:
		return factory.CleanupBehaviorPreserve
	}
}

func cleanupFactorySandboxAfterRun(ctx context.Context, deps factorySandboxExecutorDeps, req factorySandboxExecutorRequest, record factory.RunRecord, target *sandbox.SandboxState, provider sandbox.Provider, out io.Writer, behavior string, succeeded bool) error {
	switch behavior {
	case factory.CleanupBehaviorAlways:
	case factory.CleanupBehaviorOnSuccess:
		if !succeeded {
			return nil
		}
	default:
		return nil
	}
	if req.BeforeCleanup != nil {
		if err := req.BeforeCleanup(ctx, record); err != nil {
			return fmt.Errorf("prepare factory sandbox cleanup: %w", err)
		}
	}
	return deps.cleanupSandbox(ctx, factorySandboxCleanupRequest{
		Target:   target,
		Provider: provider,
		Out:      out,
	})
}

func cleanupFactorySandboxAfterFailedStart(ctx context.Context, deps factorySandboxExecutorDeps, req factorySandboxExecutorRequest, record factory.RunRecord, target *sandbox.SandboxState) error {
	if factorySandboxCleanupBehavior(record) != factory.CleanupBehaviorAlways {
		return nil
	}
	provider, err := deps.resolveProvider(target.Provider)
	if err != nil {
		return fmt.Errorf("resolve sandbox provider %q: %w", target.Provider, err)
	}
	return cleanupFactorySandboxAfterRun(ctx, deps, req, record, target, provider, req.RemoteOutput, factory.CleanupBehaviorAlways, false)
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

func (w *factorySandboxTimelineWriter) SyncNextSequence() error {
	if w == nil || strings.TrimSpace(w.runID) == "" {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	events, err := w.store.LoadEvents(w.runID)
	if err != nil {
		return fmt.Errorf("load factory sandbox timeline %q: %w", w.runID, err)
	}
	w.nextSequence = nextFactoryRunEventSequence(events)
	return nil
}

func (w *factorySandboxTimelineWriter) appendExecutorEvent(eventType, summary string, metadata map[string]any) error {
	if w == nil || strings.TrimSpace(w.runID) == "" {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	return w.appendExecutorEventLocked(eventType, summary, metadata)
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

func (w *factorySandboxTimelineWriter) appendExecutorEventLocked(eventType, summary string, metadata map[string]any) error {
	eventMetadata := map[string]any{
		"source":       "remote_sandbox",
		"step":         "run",
		"executorMode": factory.ExecutorModeSandbox,
		"sandboxName":  w.sandboxName,
		"provider":     w.provider,
	}
	for key, value := range metadata {
		eventMetadata[key] = value
	}
	event := factory.EventRecord{
		Sequence:  w.nextSequence,
		RunID:     w.runID,
		EventType: eventType,
		Timestamp: w.deps.now().UTC(),
		Summary:   summary,
		Metadata:  eventMetadata,
	}
	if err := w.deps.appendEvent(w.store, &event); err != nil {
		return err
	}
	w.nextSequence++
	return nil
}

type factorySandboxBootstrapExecutor struct {
	provider        sandbox.Provider
	connectInfo     *sandbox.ConnectInfo
	runProviderExec func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error
	out             io.Writer
}

func (e *factorySandboxBootstrapExecutor) Run(ctx context.Context, command factory.BootstrapCommand) (factory.BootstrapCommandResult, error) {
	if e == nil || e.runProviderExec == nil {
		return factory.BootstrapCommandResult{}, fmt.Errorf("sandbox bootstrap executor is required")
	}
	var summary bytes.Buffer
	out := io.Writer(&summary)
	if e.out != nil {
		out = io.MultiWriter(e.out, &summary)
	}
	err := e.runProviderExec(ctx, e.provider, e.connectInfo, factorySandboxBootstrapCommandArgs(command), out)
	return factory.BootstrapCommandResult{
		OutputSummary: strings.TrimSpace(summary.String()),
	}, err
}

func factorySandboxBootstrapCommandArgs(command factory.BootstrapCommand) []string {
	args := []string{"env"}
	for _, key := range sortedStringMapKeys(command.Env) {
		args = append(args, key+"="+command.Env[key])
	}
	args = append(args, strings.TrimSpace(command.Name))
	args = append(args, command.Args...)
	if dir := strings.TrimSpace(command.Dir); dir != "" {
		return []string{"sh", "-lc", "cd " + shellQuote(dir) + " && exec " + shellCommand(args)}
	}
	return args
}

func sortedStringMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		if strings.TrimSpace(key) != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func factorySandboxBootstrapRequest(record factory.RunRecord) (factory.BootstrapRequest, bool) {
	workspaceDir := factorySandboxRemoteWorkspaceDir(record)
	repoRemote := strings.TrimSpace(record.RepoRemote)
	baseBranch := strings.TrimSpace(record.BaseBranch)
	if workspaceDir == "" || repoRemote == "" || baseBranch == "" {
		return factory.BootstrapRequest{}, false
	}
	return factory.BootstrapRequest{
		RepositoryURL: repoRemote,
		BaseBranch:    baseBranch,
		RunBranch:     strings.TrimSpace(record.BranchName),
		WorkspaceDir:  workspaceDir,
		Options: factory.BootstrapOptions{
			RefreshHal: true,
		},
	}, true
}

func appendFactorySandboxBootstrapTimeline(store factory.Store, deps factorySandboxExecutorDeps, record *factory.RunRecord, target *sandbox.SandboxState, result factory.BootstrapResult) error {
	if record == nil || strings.TrimSpace(record.RunID) == "" || len(result.Timeline) == 0 {
		return nil
	}
	events, err := store.LoadEvents(record.RunID)
	if err != nil {
		return fmt.Errorf("load factory sandbox timeline %q: %w", record.RunID, err)
	}
	nextSequence := nextFactoryRunEventSequence(events)
	sandboxName := ""
	provider := ""
	if target != nil {
		sandboxName = target.Name
		provider = target.Provider
	}
	for _, timeline := range result.Timeline {
		eventType := factory.EventTypeStepEnded
		if timeline.Status == factory.RunStatusFailed {
			eventType = factory.EventTypeFailureClassification
		}
		metadata := map[string]any{
			"source":       "remote_sandbox",
			"phase":        "bootstrap",
			"step":         timeline.Step,
			"status":       timeline.Status,
			"executorMode": factory.ExecutorModeSandbox,
			"sandboxName":  sandboxName,
			"provider":     provider,
		}
		for key, value := range timeline.Metadata {
			metadata[key] = value
		}
		if timeline.CommandSummary != "" {
			metadata["command"] = timeline.CommandSummary
		}
		event := factory.EventRecord{
			Sequence:  nextSequence,
			RunID:     record.RunID,
			EventType: eventType,
			Timestamp: timeline.Timestamp,
			Message:   timeline.OutputSummary,
			Summary:   timeline.Message,
			Metadata:  metadata,
		}
		if event.Summary == "" {
			event.Summary = "Sandbox workspace bootstrap step recorded"
		}
		if err := deps.appendEvent(store, &event); err != nil {
			return err
		}
		nextSequence++
	}
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
	if engineName := normalizeFactoryRunEngineName(req.Engine); engineName != "" {
		args = append(args, "--engine", engineName)
	}
	if req.SkipCI {
		args = append(args, "--no-ci")
	}
	if env := factorySandboxRemoteAutoEnv(req.AttemptPolicy); len(env) > 0 {
		return append(append([]string{"env"}, env...), args...)
	}
	return args
}

func factorySandboxRemoteAutoEnv(policy autoFactoryAttemptPolicy) []string {
	env := make([]string, 0, 3)
	if policy.MaxRunAttempts > 0 {
		env = append(env, fmt.Sprintf("%s=%d", autoFactoryMaxRunAttemptsEnv, policy.MaxRunAttempts))
	}
	if policy.MaxReviewFixAttempts > 0 {
		env = append(env, fmt.Sprintf("%s=%d", autoFactoryMaxReviewFixAttemptsEnv, policy.MaxReviewFixAttempts))
	}
	if policy.MaxCIFixAttempts > 0 {
		env = append(env, fmt.Sprintf("%s=%d", autoFactoryMaxCIFixAttemptsEnv, policy.MaxCIFixAttempts))
	}
	return env
}

func factorySandboxPrepareRemoteInputs(ctx context.Context, req factorySandboxExecutorRequest, provider sandbox.Provider, target *sandbox.SandboxState, out io.Writer, deps factorySandboxExecutorDeps) (factoryRunAutoRequest, error) {
	remoteReq := req.RemoteAuto
	workspaceDir := factorySandboxRemoteWorkspaceDir(req.RunRecord)
	if workspaceDir == "" {
		return remoteReq, errFactorySandboxWorkspaceRequired
	}
	connectInfo := sandbox.ConnectInfoFromState(target)
	if len(remoteReq.Args) > 0 {
		remotePath, changed, err := factorySandboxCopyInputToRemote(ctx, req.ProjectDir, remoteReq.Args[0], workspaceDir, provider, connectInfo, out, deps)
		if err != nil {
			return remoteReq, err
		}
		if changed {
			remoteReq.Args = append([]string{remotePath}, remoteReq.Args[1:]...)
		}
	}
	if strings.TrimSpace(remoteReq.ReportPath) != "" {
		remotePath, changed, err := factorySandboxCopyInputToRemote(ctx, req.ProjectDir, remoteReq.ReportPath, workspaceDir, provider, connectInfo, out, deps)
		if err != nil {
			return remoteReq, err
		}
		if changed {
			remoteReq.ReportPath = remotePath
		}
	}
	return remoteReq, nil
}

func factorySandboxCopyInputToRemote(ctx context.Context, projectDir, localPath, workspaceDir string, provider sandbox.Provider, connectInfo *sandbox.ConnectInfo, out io.Writer, deps factorySandboxExecutorDeps) (string, bool, error) {
	localPath = strings.TrimSpace(localPath)
	if localPath == "" {
		return localPath, false, nil
	}
	sourcePath := localPath
	if !filepath.IsAbs(sourcePath) {
		sourcePath = filepath.Join(strings.TrimSpace(projectDir), sourcePath)
	}
	content, err := os.ReadFile(sourcePath)
	if err != nil {
		return localPath, false, fmt.Errorf("read sandbox input %q: %w", localPath, err)
	}
	remotePath := factorySandboxRemoteInputPath(localPath)
	remoteAbsPath := filepath.ToSlash(filepath.Join(workspaceDir, remotePath))
	encoded := base64.StdEncoding.EncodeToString(content)
	remoteDir := shellQuote(filepath.ToSlash(filepath.Dir(remoteAbsPath)))
	remoteFile := shellQuote(remoteAbsPath)
	if encoded == "" {
		args := []string{"sh", "-lc", "mkdir -p " + remoteDir + " && : > " + remoteFile}
		if err := deps.runProviderExec(ctx, provider, connectInfo, args, out); err != nil {
			return localPath, false, fmt.Errorf("copy sandbox input %q to %q: %w", localPath, remotePath, err)
		}
		return remotePath, true, nil
	}
	for offset := 0; offset < len(encoded); offset += factorySandboxCopyInputChunkEncodedBytes {
		end := offset + factorySandboxCopyInputChunkEncodedBytes
		if end > len(encoded) {
			end = len(encoded)
		}
		redirect := ">>"
		prefix := ""
		if offset == 0 {
			redirect = ">"
			prefix = "mkdir -p " + remoteDir + " && "
		}
		args := []string{"sh", "-lc", prefix + "printf %s " + shellQuote(encoded[offset:end]) + " | base64 -d " + redirect + " " + remoteFile}
		if err := deps.runProviderExec(ctx, provider, connectInfo, args, out); err != nil {
			return localPath, false, fmt.Errorf("copy sandbox input %q to %q: %w", localPath, remotePath, err)
		}
	}
	return remotePath, true, nil
}

func factorySandboxRemoteInputPath(localPath string) string {
	cleaned := filepath.ToSlash(filepath.Clean(strings.TrimSpace(localPath)))
	if cleaned == "." || cleaned == "" {
		return filepath.ToSlash(filepath.Join(".hal", "factory-inputs", "input.md"))
	}
	if filepath.IsAbs(localPath) || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		base := filepath.Base(cleaned)
		if strings.TrimSpace(base) == "" || base == "." || base == string(filepath.Separator) {
			base = "input.md"
		}
		return filepath.ToSlash(filepath.Join(".hal", "factory-inputs", base))
	}
	return cleaned
}

func factorySandboxRemoteCommandArgs(record factory.RunRecord, req factoryRunAutoRequest) []string {
	autoArgs := factorySandboxRemoteAutoArgs(req)
	workspaceDir := factorySandboxRemoteWorkspaceDir(record)
	if workspaceDir == "" {
		return autoArgs
	}
	return []string{"sh", "-lc", "cd " + shellQuote(workspaceDir) + " && exec " + shellCommand(autoArgs)}
}

func factorySandboxRemoteWorkspaceDir(record factory.RunRecord) string {
	if name := repositoryNameFromRemote(record.RepoRemote); name != "" {
		return "/workspace/" + name
	}
	if repoPath := strings.TrimSpace(record.RepoPath); strings.HasPrefix(repoPath, "/workspace/") {
		return repoPath
	}
	return ""
}

func repositoryNameFromRemote(remote string) string {
	remote = strings.TrimSuffix(strings.TrimSpace(remote), "/")
	remote = strings.TrimSuffix(remote, ".git")
	if remote == "" {
		return ""
	}
	if idx := strings.LastIndex(remote, "/"); idx >= 0 {
		remote = remote[idx+1:]
	}
	if idx := strings.LastIndex(remote, ":"); idx >= 0 {
		remote = remote[idx+1:]
	}
	return strings.TrimSpace(remote)
}

func shellCommand(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, shellQuote(arg))
	}
	return strings.Join(quoted, " ")
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
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
	if existing, err := store.LoadRun(record.RunID); err == nil && existing != nil {
		record.Artifacts = existing.Artifacts
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
	message := factorySandboxSanitizedError(target, failureErr)
	failure := factory.FailureSummary{
		Step:             step,
		Category:         factory.FailureCategoryPipeline,
		Message:          message,
		Recoverable:      true,
		SuggestedCommand: factorySandboxFailureSuggestedCommand(record),
	}
	record.Failure = &failure
	if err := deps.saveRun(store, record); err != nil {
		return err
	}
	events, err := store.LoadEvents(record.RunID)
	if err != nil {
		return fmt.Errorf("load factory sandbox timeline %q: %w", record.RunID, err)
	}
	return deps.appendEvent(store, &factory.EventRecord{
		Sequence:  nextFactoryRunEventSequence(events),
		RunID:     record.RunID,
		EventType: factory.EventTypeFailureClassification,
		Timestamp: failedAt,
		Message:   message,
		Summary:   "Sandbox factory executor failed",
		Metadata: map[string]any{
			"step":        step,
			"category":    failure.Category,
			"recoverable": failure.Recoverable,
			"source":      "remote_sandbox",
		},
	})
}

func factorySandboxSanitizedError(target *sandbox.SandboxState, err error) string {
	if err == nil {
		return "sandbox factory executor failed"
	}
	message := strings.TrimSpace(err.Error())
	if message == "" {
		message = "sandbox factory executor failed"
	}
	if target == nil {
		return message
	}
	redactor := sandboxRedactor(false, nil, target)
	return redactor.Redact(message)
}

func factorySandboxRecordedError(prefix string, target *sandbox.SandboxState, err error) error {
	return fmt.Errorf("%s: %s", prefix, factorySandboxSanitizedError(target, err))
}

func factorySandboxFailureSuggestedCommand(record *factory.RunRecord) string {
	if record == nil {
		return ""
	}
	if record.Sandbox != nil {
		if command := strings.TrimSpace(record.Sandbox.SSHCommand); command != "" {
			return command
		}
	}
	if name := strings.TrimSpace(record.SandboxName); name != "" {
		return fmt.Sprintf("hal sandbox ssh %s", name)
	}
	return factoryRunInspectCommand(record.RunID)
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
		Address:           sandbox.PreferredIP(instance),
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

func cleanupFactorySandbox(ctx context.Context, req factorySandboxCleanupRequest) error {
	_ = ctx
	if req.Target == nil || strings.TrimSpace(req.Target.Name) == "" {
		return nil
	}
	if req.Provider == nil {
		return fmt.Errorf("sandbox cleanup provider is required")
	}
	return runSandboxDeleteWithDeps([]string{req.Target.Name}, false, true, "", nil, req.Out, req.Provider)
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
