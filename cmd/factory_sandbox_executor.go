package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	pathpkg "path"
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

type factorySandboxAuthFile struct {
	SourcePath string
	RemotePath string
}

type factorySandboxExecutorRequest struct {
	ProjectDir          string
	SandboxName         string
	RunRecord           factory.RunRecord
	ResolvedSecrets     []factory.ResolvedRunSecret
	RemoteAuto          factoryRunAutoRequest
	RemoteOutput        io.Writer
	BeforeCleanup       func(context.Context, factory.RunRecord) error
	DeferSuccessCleanup bool
}

type factorySandboxExecutorDeps struct {
	defaultStore           func() (factory.Store, error)
	now                    func() time.Time
	resolveDefault         func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error)
	loadSandbox            func(string) (*sandbox.SandboxState, error)
	provision              func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error)
	startSandbox           func(context.Context, *sandbox.SandboxState, io.Writer) (*sandbox.SandboxState, error)
	resolveProvider        func(string) (sandbox.Provider, error)
	runProviderExec        func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error
	runProviderScript      func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error
	runProviderExecWithEnv func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, map[string]string, io.Writer) error
	engineAuthFiles        func() []factorySandboxAuthFile
	bootstrap              func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error)
	cleanupSandbox         func(context.Context, factorySandboxCleanupRequest) error
	saveRun                func(factory.Store, *factory.RunRecord) error
	appendEvent            func(factory.Store, *factory.EventRecord) error
	appendLog              func(factory.Store, *factory.LogChunk) error
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
	runProviderExec:        runFactorySandboxProviderExec,
	runProviderScript:      runFactorySandboxProviderScript,
	runProviderExecWithEnv: runFactorySandboxProviderExecWithEnv,
	engineAuthFiles:        factorySandboxEngineAuthFiles,
	bootstrap:              factory.BootstrapWorkspace,
	cleanupSandbox:         cleanupFactorySandbox,
	saveRun:                saveFactorySandboxRunRecord,
	appendEvent:            appendFactorySandboxTimelineEvent,
	appendLog:              appendFactorySandboxLogChunk,
}

var errFactorySandboxWorkspaceRequired = errors.New("sandbox workspace directory is required; configure remote.origin.url or run from a remote workspace checkout")

const factorySandboxCopyInputChunkEncodedBytes = 32 * 1024

const factorySandboxRemoteWorkspaceRoot = "/root/workspace"

func normalizeFactorySandboxExecutorDeps(deps factorySandboxExecutorDeps) factorySandboxExecutorDeps {
	customRunProviderExec := deps.runProviderExec != nil
	customRunProviderScript := deps.runProviderScript != nil
	customRunProviderExecWithEnv := deps.runProviderExecWithEnv != nil
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
	if deps.runProviderScript == nil {
		if customRunProviderExec {
			runProviderExec := deps.runProviderExec
			deps.runProviderScript = func(ctx context.Context, provider sandbox.Provider, info *sandbox.ConnectInfo, script string, out io.Writer) error {
				return runProviderExec(ctx, provider, info, []string{"sh", "-c", script}, out)
			}
		} else {
			deps.runProviderScript = defaultFactorySandboxExecutorDeps.runProviderScript
		}
	}
	if deps.runProviderExecWithEnv == nil {
		if customRunProviderExec {
			runProviderExec := deps.runProviderExec
			deps.runProviderExecWithEnv = func(ctx context.Context, provider sandbox.Provider, info *sandbox.ConnectInfo, args []string, _ map[string]string, out io.Writer) error {
				return runProviderExec(ctx, provider, info, args, out)
			}
		} else {
			deps.runProviderExecWithEnv = defaultFactorySandboxExecutorDeps.runProviderExecWithEnv
		}
	}
	if deps.engineAuthFiles == nil {
		if customRunProviderExec || customRunProviderScript || customRunProviderExecWithEnv {
			deps.engineAuthFiles = func() []factorySandboxAuthFile { return nil }
		} else {
			deps.engineAuthFiles = defaultFactorySandboxExecutorDeps.engineAuthFiles
		}
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
	if deps.appendLog == nil {
		deps.appendLog = defaultFactorySandboxExecutorDeps.appendLog
	}
	return deps
}

func runFactorySandboxExecutorWithDeps(ctx context.Context, req factorySandboxExecutorRequest, deps factorySandboxExecutorDeps) (returnErr error) {
	deps = normalizeFactorySandboxExecutorDeps(deps)
	if ctx == nil {
		ctx = context.Background()
	}
	secretRedactor := factory.NewRunSecretRedactor(req.ResolvedSecrets)

	store, err := deps.defaultStore()
	if err != nil {
		return fmt.Errorf("open factory store: %w", err)
	}

	record := req.RunRecord
	record.ExecutorMode = factory.ExecutorModeSandbox
	record.UpdatedAt = deps.now().UTC()
	if err := saveFactorySandboxRunRecordWithRedactor(store, deps, &record, secretRedactor); err != nil {
		return fmt.Errorf("save sandbox factory run: %w", err)
	}
	// Sandbox create persists Repo as an informational label; bootstrap uses
	// record.RepoRemote directly for the actual clone.
	provisionRepo := redactFactorySandboxProvisionRepo(record, secretRedactor)

	if factorySandboxRemoteWorkspaceDir(record) == "" {
		_ = recordFactorySandboxFailure(store, deps, &record, nil, "prepare_inputs", errFactorySandboxWorkspaceRequired, secretRedactor)
		return factorySandboxRecordedError("prepare factory sandbox inputs", nil, errFactorySandboxWorkspaceRequired, secretRedactor)
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
				Repo:       provisionRepo,
				Out:        req.RemoteOutput,
			})
			if err != nil {
				_ = recordFactorySandboxFailure(store, deps, &record, nil, "provision", err, secretRedactor)
				return factorySandboxRecordedError("provision factory sandbox", nil, err, secretRedactor)
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
					Repo:       provisionRepo,
					Out:        req.RemoteOutput,
				})
				if err != nil {
					_ = recordFactorySandboxFailure(store, deps, &record, nil, "provision", err, secretRedactor)
					return factorySandboxRecordedError("provision factory sandbox", nil, err, secretRedactor)
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
			_ = recordFactorySandboxFailure(store, deps, &record, target, "start", err, secretRedactor)
			startErr := factorySandboxRecordedError(fmt.Sprintf("start factory sandbox %q", target.Name), target, err, secretRedactor)
			if cleanupErr := cleanupFactorySandboxAfterFailedStart(ctx, store, deps, req, record, target); cleanupErr != nil {
				sanitizedCleanupErr := fmt.Errorf("%s", factorySandboxSanitizedError(target, fmt.Errorf("cleanup factory sandbox: %w", cleanupErr), secretRedactor))
				return errors.Join(startErr, sanitizedCleanupErr)
			}
			return startErr
		}
		target = startedTarget
	}

	record.SandboxName, record.Sandbox = factorySandboxMetadataFromState(target)
	record.UpdatedAt = deps.now().UTC()
	if err := saveFactorySandboxRunRecordWithRedactor(store, deps, &record, secretRedactor); err != nil {
		return fmt.Errorf("record factory sandbox metadata: %w", err)
	}

	remoteOutput := newFactorySandboxTimelineWriter(store, deps, &record, target, req.RemoteOutput, req.ResolvedSecrets)
	provider, err := deps.resolveProvider(target.Provider)
	if err != nil {
		_ = recordFactorySandboxFailure(store, deps, &record, target, "resolve_provider", err, secretRedactor)
		return factorySandboxRecordedError(fmt.Sprintf("resolve sandbox provider %q", target.Provider), target, err, secretRedactor)
	}
	cleanupBehavior := factorySandboxCleanupBehavior(record)
	if req.DeferSuccessCleanup && cleanupBehavior == factory.CleanupBehaviorOnSuccess {
		cleanupBehavior = factory.CleanupBehaviorPreserve
	}
	cleanupSucceeded := false
	defer func() {
		deferredCleanupBehavior := cleanupBehavior
		if req.DeferSuccessCleanup && returnErr == nil && cleanupBehavior == factory.CleanupBehaviorAlways {
			deferredCleanupBehavior = factory.CleanupBehaviorPreserve
		}
		cleaned, cleanupErr := cleanupFactorySandboxAfterRun(ctx, deps, req, record, target, provider, req.RemoteOutput, deferredCleanupBehavior, cleanupSucceeded)
		if cleaned {
			if recordErr := recordFactorySandboxCleanedUp(store, deps, &record, target, secretRedactor); recordErr != nil {
				if cleanupErr != nil {
					cleanupErr = errors.Join(cleanupErr, recordErr)
				} else {
					cleanupErr = recordErr
				}
			}
		}
		if cleanupErr != nil {
			sanitizedCleanupErr := fmt.Errorf("%s", factorySandboxSanitizedError(target, fmt.Errorf("cleanup factory sandbox: %w", cleanupErr), secretRedactor))
			if returnErr != nil {
				returnErr = errors.Join(returnErr, sanitizedCleanupErr)
				return
			}
			returnErr = sanitizedCleanupErr
		}
	}()

	if bootstrapReq, ok := factorySandboxBootstrapRequest(record, req.ResolvedSecrets); ok {
		connectInfo := sandbox.ConnectInfoFromState(target)
		bootstrapResult, bootstrapErr := deps.bootstrap(ctx, bootstrapReq, factory.BootstrapDeps{
			Executor: &factorySandboxBootstrapExecutor{
				provider:               provider,
				connectInfo:            connectInfo,
				runProviderExecWithEnv: deps.runProviderExecWithEnv,
				// Bootstrap timelines are persisted from sanitized BootstrapResult
				// events; stream redacted command output to the caller-facing writer.
				out:          req.RemoteOutput,
				outputRedact: factory.NewBootstrapSanitizer(bootstrapReq).SanitizeString,
			},
			Now: deps.now,
			RepoExists: func(path string) (bool, error) {
				return factorySandboxRemoteRepoExists(ctx, provider, connectInfo, deps.runProviderScript, path, bootstrapReq.RepositoryURL)
			},
		})
		if appendErr := appendFactorySandboxBootstrapTimeline(store, deps, &record, target, bootstrapResult, remoteOutput); appendErr != nil {
			return fmt.Errorf("record sandbox bootstrap timeline: %w", appendErr)
		}
		if syncErr := remoteOutput.SyncNextSequence(); syncErr != nil {
			return fmt.Errorf("sync sandbox timeline sequence: %w", syncErr)
		}
		if bootstrapErr != nil {
			_ = recordFactorySandboxFailure(store, deps, &record, target, "bootstrap", bootstrapErr, secretRedactor)
			return factorySandboxRecordedError("bootstrap factory sandbox workspace", target, bootstrapErr, secretRedactor)
		}
	}

	if err := factorySandboxSyncEngineAuth(ctx, provider, target, remoteOutput, deps); err != nil {
		_ = recordFactorySandboxFailure(store, deps, &record, target, "prepare_auth", err, secretRedactor)
		return factorySandboxRecordedError("prepare factory sandbox auth", target, err, secretRedactor)
	}

	remoteAuto, err := factorySandboxPrepareRemoteInputs(ctx, req, provider, target, remoteOutput, deps)
	if err != nil {
		_ = recordFactorySandboxFailure(store, deps, &record, target, "prepare_inputs", err, secretRedactor)
		return factorySandboxRecordedError("prepare factory sandbox inputs", target, err, secretRedactor)
	}

	remoteArgs := factorySandboxRemoteCommandArgs(record, remoteAuto)
	if err := remoteOutput.appendExecutorEvent(factory.EventTypeStepStarted, "Remote sandbox execution started", map[string]any{
		"command": strings.Join(remoteArgs, " "),
		"status":  factory.RunStatusRunning,
	}); err != nil {
		return fmt.Errorf("record remote sandbox start: %w", err)
	}
	runErr := deps.runProviderExecWithEnv(ctx, provider, sandbox.ConnectInfoFromState(target), remoteArgs, factorySandboxResolvedSecretEnv(req.ResolvedSecrets), remoteOutput)
	flushErr := remoteOutput.Flush()
	if runErr != nil {
		if flushErr != nil {
			runErr = errors.Join(runErr, fmt.Errorf("record remote sandbox output: %w", flushErr))
		}
		sanitizedErr := factorySandboxSanitizedError(target, runErr, secretRedactor)
		_ = recordFactorySandboxFailure(store, deps, &record, target, "run", runErr, secretRedactor)
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
	if !req.DeferSuccessCleanup {
		cleanupSucceeded = true
	}
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

func cleanupFactorySandboxAfterRun(ctx context.Context, deps factorySandboxExecutorDeps, req factorySandboxExecutorRequest, record factory.RunRecord, target *sandbox.SandboxState, provider sandbox.Provider, out io.Writer, behavior string, succeeded bool) (bool, error) {
	switch behavior {
	case factory.CleanupBehaviorAlways:
	case factory.CleanupBehaviorOnSuccess:
		if !succeeded {
			return false, nil
		}
	default:
		return false, nil
	}
	if req.BeforeCleanup != nil {
		if err := req.BeforeCleanup(ctx, record); err != nil {
			return false, fmt.Errorf("prepare factory sandbox cleanup: %w", err)
		}
	}
	if err := deps.cleanupSandbox(ctx, factorySandboxCleanupRequest{
		Target:   target,
		Provider: provider,
		Out:      out,
	}); err != nil {
		return false, err
	}
	return true, nil
}

func cleanupFactorySandboxAfterFailedStart(ctx context.Context, store factory.Store, deps factorySandboxExecutorDeps, req factorySandboxExecutorRequest, record factory.RunRecord, target *sandbox.SandboxState) error {
	if factorySandboxCleanupBehavior(record) != factory.CleanupBehaviorAlways {
		return nil
	}
	secretRedactor := factory.NewRunSecretRedactor(req.ResolvedSecrets)
	provider, err := deps.resolveProvider(target.Provider)
	if err != nil {
		return fmt.Errorf("resolve sandbox provider %q: %w", target.Provider, err)
	}
	cleaned, cleanupErr := cleanupFactorySandboxAfterRun(ctx, deps, req, record, target, provider, req.RemoteOutput, factory.CleanupBehaviorAlways, false)
	if cleaned {
		if recordErr := recordFactorySandboxCleanedUp(store, deps, &record, target, secretRedactor); recordErr != nil {
			if cleanupErr != nil {
				cleanupErr = errors.Join(cleanupErr, recordErr)
			} else {
				cleanupErr = recordErr
			}
		}
	}
	return cleanupErr
}

type factorySandboxTimelineWriter struct {
	mu           sync.Mutex
	dst          io.Writer
	store        factory.Store
	deps         factorySandboxExecutorDeps
	runID        string
	sandboxName  string
	provider     string
	eventRedact  func(string) string
	outputRedact func(string) string
	pending      string
	nextSequence int64
}

func newFactorySandboxTimelineWriter(store factory.Store, deps factorySandboxExecutorDeps, record *factory.RunRecord, target *sandbox.SandboxState, dst io.Writer, secrets []factory.ResolvedRunSecret) *factorySandboxTimelineWriter {
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
	secretRedactor := factory.NewRunSecretRedactor(secrets)
	redactOutput := func(value string) string {
		return sanitizeCredentialedRemoteReferences(secretRedactor.RedactString(redactor.Redact(value)))
	}
	redactEvent := func(value string) string {
		return sanitizeFactoryLogText(redactOutput(value))
	}
	return &factorySandboxTimelineWriter{
		dst:          dst,
		store:        store,
		deps:         deps,
		runID:        runID,
		sandboxName:  sandboxName,
		provider:     provider,
		eventRedact:  redactEvent,
		outputRedact: redactOutput,
		nextSequence: nextSequence,
	}
}

func (w *factorySandboxTimelineWriter) Write(p []byte) (int, error) {
	if w == nil {
		return len(p), nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

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
	rawLine := w.pending
	w.pending = ""
	if line == "" {
		if rawLine != "" {
			return w.writeOutputLocked(rawLine)
		}
		return nil
	}
	if err := w.writeOutputLocked(rawLine); err != nil {
		return err
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
		rawLine := w.pending[:idx+1]
		w.pending = w.pending[idx+1:]
		if err := w.writeOutputLocked(rawLine); err != nil {
			return err
		}
		if line == "" {
			continue
		}
		if err := w.appendLineLocked(line); err != nil {
			return err
		}
	}
}

func (w *factorySandboxTimelineWriter) writeOutputLocked(line string) error {
	if w.dst == nil || line == "" {
		return nil
	}
	if w.outputRedact != nil {
		line = w.outputRedact(line)
	}
	_, err := w.dst.Write([]byte(line))
	return err
}

func (w *factorySandboxTimelineWriter) appendLineLocked(line string) error {
	if strings.TrimSpace(w.runID) == "" {
		return nil
	}
	if w.eventRedact != nil {
		line = w.eventRedact(line)
	}
	metadata := map[string]any{
		"source":      "remote_sandbox",
		"stream":      "remote",
		"sandboxName": w.sandboxName,
		"provider":    w.provider,
	}
	event := factory.EventRecord{
		Sequence:  w.nextSequence,
		RunID:     w.runID,
		EventType: factory.EventTypeCommandOutputSummary,
		Timestamp: w.deps.now().UTC(),
		Message:   line,
		Summary:   "Remote sandbox output",
		Metadata:  w.redactExecutorEventMetadataWithRaw(metadata),
	}
	if err := w.deps.appendEvent(w.store, &event); err != nil {
		return err
	}
	if w.deps.appendLog != nil {
		if err := w.deps.appendLog(w.store, &factory.LogChunk{
			RunID:     w.runID,
			Stream:    factory.LogStreamStdout,
			Source:    factory.LogSourceRemoteSandbox,
			Text:      line,
			Summary:   "Remote sandbox output",
			CreatedAt: event.Timestamp,
		}); err != nil {
			return err
		}
	}
	w.nextSequence++
	return nil
}

func (w *factorySandboxTimelineWriter) appendExecutorEventLocked(eventType, summary string, metadata map[string]any) error {
	eventMetadata := map[string]any{
		"source":       "remote_sandbox",
		"step":         factory.RunDurationStepEngineRun,
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
		Summary:   w.redactExecutorEventString(summary),
		Metadata:  w.redactExecutorEventMetadataWithRaw(eventMetadata),
	}
	if err := w.deps.appendEvent(w.store, &event); err != nil {
		return err
	}
	w.nextSequence++
	return nil
}

func (w *factorySandboxTimelineWriter) redactExecutorEventString(value string) string {
	if w.eventRedact == nil {
		return value
	}
	return w.eventRedact(value)
}

func (w *factorySandboxTimelineWriter) redactExecutorEventMetadata(metadata map[string]any) map[string]any {
	return w.redactExecutorEventMetadataWithRaw(metadata)
}

func (w *factorySandboxTimelineWriter) redactExecutorEventMetadataWithRaw(metadata map[string]any) map[string]any {
	if len(metadata) == 0 {
		return nil
	}
	out := make(map[string]any, len(metadata))
	for key, value := range metadata {
		redactedKey := w.redactExecutorEventString(key)
		redactedValue := w.redactExecutorEventValue(value)
		if key == "command" {
			redactedValue = w.preserveRedactedCommandMarker(value, redactedValue)
		}
		out[redactedKey] = redactedValue
	}
	return out
}

func (w *factorySandboxTimelineWriter) preserveRedactedCommandMarker(rawValue any, redactedValue any) any {
	redactedString, ok := redactedValue.(string)
	if !ok || redactedString != "[redacted]" || w.outputRedact == nil {
		return redactedValue
	}
	rawString, ok := rawValue.(string)
	if !ok {
		return redactedValue
	}
	outputRedacted := strings.TrimSpace(w.outputRedact(rawString))
	if strings.Contains(outputRedacted, factory.RunSecretRedactionPlaceholder) {
		return outputRedacted
	}
	return redactedValue
}

func (w *factorySandboxTimelineWriter) redactExecutorEventValue(value any) any {
	switch v := value.(type) {
	case string:
		return w.redactExecutorEventString(v)
	case []string:
		out := make([]string, len(v))
		for i, item := range v {
			out[i] = w.redactExecutorEventString(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = w.redactExecutorEventValue(item)
		}
		return out
	case map[string]string:
		out := make(map[string]string, len(v))
		for key, item := range v {
			out[w.redactExecutorEventString(key)] = w.redactExecutorEventString(item)
		}
		return out
	case map[string]any:
		return w.redactExecutorEventMetadata(v)
	default:
		return value
	}
}

type factorySandboxBootstrapExecutor struct {
	provider               sandbox.Provider
	connectInfo            *sandbox.ConnectInfo
	runProviderExecWithEnv func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, map[string]string, io.Writer) error
	out                    io.Writer
	outputRedact           func(string) string
}

func (e *factorySandboxBootstrapExecutor) Run(ctx context.Context, command factory.BootstrapCommand) (factory.BootstrapCommandResult, error) {
	if e == nil || e.runProviderExecWithEnv == nil {
		return factory.BootstrapCommandResult{}, fmt.Errorf("sandbox bootstrap executor is required")
	}
	var summary bytes.Buffer
	out := io.Writer(&summary)
	var streamOut *factorySandboxBootstrapOutputWriter
	if e.out != nil {
		streamOut = &factorySandboxBootstrapOutputWriter{
			dst:    e.out,
			redact: e.outputRedact,
		}
		out = io.MultiWriter(streamOut, &summary)
	}
	err := e.runProviderExecWithEnv(ctx, e.provider, e.connectInfo, factorySandboxBootstrapCommandArgs(command), command.Env, out)
	if streamOut != nil {
		if flushErr := streamOut.Flush(); err == nil && flushErr != nil {
			err = flushErr
		}
	}
	return factory.BootstrapCommandResult{
		ExitCode:      factorySandboxExecExitCode(err),
		OutputSummary: strings.TrimSpace(summary.String()),
	}, err
}

func factorySandboxExecExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr interface {
		ExitCode() int
	}
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 0
}

func factorySandboxRemoteRepoExists(ctx context.Context, provider sandbox.Provider, info *sandbox.ConnectInfo, runProviderScript func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error, repoPath string, expectedRemote string) (bool, error) {
	if runProviderScript == nil {
		return false, fmt.Errorf("sandbox exec dependency is required")
	}
	repoPath = filepath.ToSlash(filepath.Clean(strings.TrimSpace(repoPath)))
	if repoPath == "" || repoPath == "." {
		return false, errFactorySandboxWorkspaceRequired
	}
	repoGitPath := filepath.ToSlash(filepath.Join(repoPath, ".git"))
	quotedRepoPath := shellQuote(repoPath)
	script := strings.Join([]string{
		"if [ -e " + shellQuote(repoGitPath) + " ]; then git -C " + quotedRepoPath + " remote get-url origin; exit $?; fi",
		"if [ ! -e " + quotedRepoPath + " ]; then exit 10; fi",
		"if [ -d " + quotedRepoPath + " ] && [ -z \"$(find " + quotedRepoPath + " -mindepth 1 -maxdepth 1 -print -quit)\" ]; then exit 10; fi",
		"exit 11",
	}, "\n")
	var output bytes.Buffer
	err := runProviderScript(ctx, provider, info, script, &output)
	if err == nil {
		if !factorySandboxRemoteMatches(expectedRemote, output.String()) {
			return false, fmt.Errorf("existing checkout origin does not match requested repository")
		}
		return true, nil
	}
	switch factorySandboxExecExitCode(err) {
	case 10:
		return false, nil
	case 11:
		return false, fmt.Errorf("repository path exists but is not a git checkout and is not empty")
	default:
		return false, err
	}
}

type factorySandboxBootstrapOutputWriter struct {
	dst     io.Writer
	redact  func(string) string
	pending string
}

func (w *factorySandboxBootstrapOutputWriter) Write(p []byte) (int, error) {
	if w == nil {
		return len(p), nil
	}
	w.pending += string(p)
	for {
		idx := strings.IndexByte(w.pending, '\n')
		if idx < 0 {
			return len(p), nil
		}
		line := w.pending[:idx+1]
		w.pending = w.pending[idx+1:]
		if err := w.write(line); err != nil {
			return 0, err
		}
	}
}

func (w *factorySandboxBootstrapOutputWriter) Flush() error {
	if w == nil || w.pending == "" {
		return nil
	}
	line := w.pending
	w.pending = ""
	return w.write(line)
}

func (w *factorySandboxBootstrapOutputWriter) write(line string) error {
	if w.dst == nil || line == "" {
		return nil
	}
	if w.redact != nil {
		line = w.redact(line)
	}
	_, err := w.dst.Write([]byte(line))
	return err
}

func factorySandboxBootstrapCommandArgs(command factory.BootstrapCommand) []string {
	args := []string{strings.TrimSpace(command.Name)}
	args = append(args, command.Args...)
	if dir := strings.TrimSpace(command.Dir); dir != "" {
		if strings.TrimSpace(command.Name) == "hal" {
			return []string{"sh", "-c", "set -eu\ncd " + shellQuote(dir) + "\n" + factorySandboxRemoteHalScript(command.Args)}
		}
		return []string{"sh", "-c", "cd " + shellQuote(dir) + " && exec " + shellCommand(args)}
	}
	if strings.TrimSpace(command.Name) == "hal" {
		return []string{"sh", "-c", factorySandboxRemoteHalScript(command.Args)}
	}
	return args
}

func factorySandboxRemoteHalScript(args []string) string {
	return factorySandboxRemoteHalScriptWithEnv(args, nil)
}

func factorySandboxRemoteHalScriptWithEnv(args []string, env []string) string {
	command := `exec "$HOME/.local/bin/hal"`
	if len(args) > 0 {
		command += " " + shellCommand(args)
	}
	lines := []string{
		"set -eu",
		`remote_home="${HOME:-}"`,
		`if [ -z "$remote_home" ] && command -v getent >/dev/null 2>&1; then`,
		`  remote_home="$(getent passwd "$(id -u)" | cut -d: -f6)"`,
		`fi`,
		`if [ -z "$remote_home" ]; then remote_home="$(pwd)"; fi`,
		`export HOME="$remote_home"`,
	}
	for _, assignment := range env {
		if trimmed := strings.TrimSpace(assignment); trimmed != "" {
			lines = append(lines, "export "+trimmed)
		}
	}
	lines = append(lines, command)
	return strings.Join(lines, "\n")
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

func factorySandboxBootstrapRequest(record factory.RunRecord, secrets []factory.ResolvedRunSecret) (factory.BootstrapRequest, bool) {
	workspaceDir := factorySandboxRemoteWorkspaceDir(record)
	repoRemote := strings.TrimSpace(record.RepoRemote)
	baseBranch := strings.TrimSpace(record.BaseBranch)
	if workspaceDir == "" || repoRemote == "" || baseBranch == "" {
		return factory.BootstrapRequest{}, false
	}
	request := factory.BootstrapRequest{
		RepositoryURL:   repoRemote,
		BaseBranch:      baseBranch,
		RunBranch:       strings.TrimSpace(record.BranchName),
		WorkspaceDir:    workspaceDir,
		RequiredEnvKeys: factorySandboxBootstrapRequiredEnvKeys(record.Secrets),
		Env:             factorySandboxResolvedSecretEnv(secrets),
		Options: factory.BootstrapOptions{
			RefreshHal: true,
		},
	}
	return factory.BootstrapRequestWithResolvedSecrets(request, secrets), true
}

func factorySandboxBootstrapRequiredEnvKeys(secrets []factory.RunSecretMetadata) []string {
	keys := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		if !secret.Required || strings.TrimSpace(secret.Source) != factory.RunSecretSourceEnv {
			continue
		}
		if name := strings.TrimSpace(secret.Name); name != "" {
			keys = append(keys, name)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Strings(keys)
	return keys
}

func factorySandboxResolvedSecretEnv(secrets []factory.ResolvedRunSecret) map[string]string {
	env := make(map[string]string, len(secrets))
	for _, secret := range secrets {
		if strings.TrimSpace(secret.Source) != factory.RunSecretSourceEnv {
			continue
		}
		name := strings.TrimSpace(secret.Name)
		if name == "" || strings.TrimSpace(secret.Value) == "" {
			continue
		}
		env[name] = secret.Value
	}
	if len(env) == 0 {
		return nil
	}
	return env
}

func appendFactorySandboxBootstrapTimeline(store factory.Store, deps factorySandboxExecutorDeps, record *factory.RunRecord, target *sandbox.SandboxState, result factory.BootstrapResult, redactor *factorySandboxTimelineWriter) error {
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
		if redactor != nil {
			event.Message = redactor.redactExecutorEventString(event.Message)
			event.Summary = redactor.redactExecutorEventString(event.Summary)
			event.Metadata = redactor.redactExecutorEventMetadataWithRaw(metadata)
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
	args := []string{"auto"}
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
	return args
}

func factorySandboxRemoteAutoScript(req factoryRunAutoRequest) string {
	return factorySandboxRemoteHalScriptWithEnv(factorySandboxRemoteAutoArgs(req), factorySandboxRemoteAutoEnv(req.AttemptPolicy))
}

func factorySandboxRemoteAutoEnv(policy autoFactoryAttemptPolicy) []string {
	env := make([]string, 0, 3)
	env = append(env, fmt.Sprintf("%s=%d", autoFactoryMaxRunAttemptsEnv, policy.MaxRunAttempts))
	env = append(env, fmt.Sprintf("%s=%d", autoFactoryMaxReviewFixAttemptsEnv, policy.MaxReviewFixAttempts))
	env = append(env, fmt.Sprintf("%s=%d", autoFactoryMaxCIFixAttemptsEnv, policy.MaxCIFixAttempts))
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

func factorySandboxSyncEngineAuth(ctx context.Context, provider sandbox.Provider, target *sandbox.SandboxState, out io.Writer, deps factorySandboxExecutorDeps) error {
	deps = normalizeFactorySandboxExecutorDeps(deps)
	if deps.engineAuthFiles == nil {
		return nil
	}
	connectInfo := sandbox.ConnectInfoFromState(target)
	for _, authFile := range deps.engineAuthFiles() {
		sourcePath := strings.TrimSpace(authFile.SourcePath)
		remotePath := strings.TrimSpace(authFile.RemotePath)
		if sourcePath == "" || remotePath == "" {
			continue
		}
		content, err := os.ReadFile(sourcePath)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read sandbox engine auth %q: %w", filepath.Base(sourcePath), err)
		}
		var copyErr error
		if factorySandboxAuthRemotePathIsHomeRelative(remotePath) {
			copyErr = factorySandboxCopyContentToRemoteHome(ctx, content, remotePath, "0600", provider, connectInfo, out, deps)
		} else {
			copyErr = factorySandboxCopyContentToRemote(ctx, content, remotePath, "0600", provider, connectInfo, out, deps)
		}
		if copyErr != nil {
			return fmt.Errorf("sync sandbox engine auth %q: %w", filepath.Base(sourcePath), copyErr)
		}
	}
	return nil
}

func factorySandboxEngineAuthFiles() []factorySandboxAuthFile {
	candidates := []factorySandboxAuthFile{}
	if codexHome := factorySandboxCodexHome(); codexHome != "" {
		candidates = append(candidates,
			factorySandboxAuthFile{SourcePath: filepath.Join(codexHome, "auth.json"), RemotePath: ".codex/auth.json"},
			factorySandboxAuthFile{SourcePath: filepath.Join(codexHome, "config.toml"), RemotePath: ".codex/config.toml"},
		)
	}
	candidates = append(candidates, factorySandboxPiAuthFileCandidates()...)

	files := make([]factorySandboxAuthFile, 0, len(candidates))
	seen := map[string]bool{}
	for _, candidate := range candidates {
		sourcePath := strings.TrimSpace(candidate.SourcePath)
		remotePath := strings.TrimSpace(candidate.RemotePath)
		if sourcePath == "" || remotePath == "" || seen[sourcePath+"=>"+remotePath] {
			continue
		}
		info, err := os.Stat(sourcePath)
		if err != nil || info.IsDir() {
			continue
		}
		files = append(files, factorySandboxAuthFile{SourcePath: sourcePath, RemotePath: remotePath})
		seen[sourcePath+"=>"+remotePath] = true
	}
	return files
}

func factorySandboxCodexHome() string {
	if home := strings.TrimSpace(os.Getenv("CODEX_HOME")); home != "" {
		return home
	}
	if home := strings.TrimSpace(os.Getenv("HOME")); home != "" {
		return filepath.Join(home, ".codex")
	}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, ".codex")
	}
	return ""
}

func factorySandboxPiAuthFileCandidates() []factorySandboxAuthFile {
	dirs := []string{}
	if piHome := strings.TrimSpace(os.Getenv("PI_HOME")); piHome != "" {
		dirs = append(dirs, piHome, filepath.Join(piHome, "agent"))
	}
	if home := strings.TrimSpace(os.Getenv("HOME")); home != "" {
		dirs = append(dirs, filepath.Join(home, ".pi", "agent"))
	} else if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		dirs = append(dirs, filepath.Join(home, ".pi", "agent"))
	}

	files := make([]factorySandboxAuthFile, 0, len(dirs)*3)
	for _, dir := range dirs {
		files = append(files,
			factorySandboxAuthFile{SourcePath: filepath.Join(dir, "auth.json"), RemotePath: ".pi/agent/auth.json"},
			factorySandboxAuthFile{SourcePath: filepath.Join(dir, "settings.json"), RemotePath: ".pi/agent/settings.json"},
			factorySandboxAuthFile{SourcePath: filepath.Join(dir, "trust.json"), RemotePath: ".pi/agent/trust.json"},
		)
	}
	return files
}

func factorySandboxAuthRemotePathIsHomeRelative(remotePath string) bool {
	remotePath = strings.TrimSpace(remotePath)
	if remotePath == "" {
		return false
	}
	return !pathpkg.IsAbs(filepath.ToSlash(remotePath))
}

func factorySandboxCopyInputToRemote(ctx context.Context, projectDir, localPath, workspaceDir string, provider sandbox.Provider, connectInfo *sandbox.ConnectInfo, out io.Writer, deps factorySandboxExecutorDeps) (string, bool, error) {
	deps = normalizeFactorySandboxExecutorDeps(deps)
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
	if err := factorySandboxCopyContentToRemote(ctx, content, remoteAbsPath, "", provider, connectInfo, out, deps); err != nil {
		return localPath, false, fmt.Errorf("copy sandbox input %q to %q: %w", localPath, remotePath, err)
	}
	return remotePath, true, nil
}

func factorySandboxCopyContentToRemote(ctx context.Context, content []byte, remoteAbsPath, mode string, provider sandbox.Provider, connectInfo *sandbox.ConnectInfo, out io.Writer, deps factorySandboxExecutorDeps) error {
	deps = normalizeFactorySandboxExecutorDeps(deps)
	encoded := base64.StdEncoding.EncodeToString(content)
	remoteAbsPath = filepath.ToSlash(filepath.Clean(strings.TrimSpace(remoteAbsPath)))
	if remoteAbsPath == "" || remoteAbsPath == "." {
		return fmt.Errorf("remote path is required")
	}
	remoteDir := filepath.ToSlash(filepath.Dir(remoteAbsPath))
	remoteFile := remoteAbsPath
	remoteTmp := factorySandboxRemoteTempPath(remoteDir, remoteFile, content)
	pathScript := factorySandboxRemoteAbsolutePathScript(remoteDir, remoteFile, remoteTmp)
	if encoded == "" {
		script := pathScript + "\n" + factorySandboxRemoteBeginCopyScript() + "\n" + factorySandboxRemoteFinalizeCopyScript(mode)
		if err := deps.runProviderScript(ctx, provider, connectInfo, script, out); err != nil {
			return err
		}
		return nil
	}
	for offset := 0; offset < len(encoded); offset += factorySandboxCopyInputChunkEncodedBytes {
		end := offset + factorySandboxCopyInputChunkEncodedBytes
		if end > len(encoded) {
			end = len(encoded)
		}
		copyScript := factorySandboxRemoteContinueCopyScript()
		if offset == 0 {
			copyScript = factorySandboxRemoteBeginCopyScript()
		}
		script := pathScript + "\n" + copyScript + "\nprintf %s " + shellQuote(encoded[offset:end]) + " | base64 -d >> \"$remote_tmp\""
		if err := deps.runProviderScript(ctx, provider, connectInfo, script, out); err != nil {
			return err
		}
	}
	if err := deps.runProviderScript(ctx, provider, connectInfo, pathScript+"\n"+factorySandboxRemoteFinalizeCopyScript(mode), out); err != nil {
		return err
	}
	return nil
}

func factorySandboxCopyContentToRemoteHome(ctx context.Context, content []byte, remoteRelPath, mode string, provider sandbox.Provider, connectInfo *sandbox.ConnectInfo, out io.Writer, deps factorySandboxExecutorDeps) error {
	deps = normalizeFactorySandboxExecutorDeps(deps)
	encoded := base64.StdEncoding.EncodeToString(content)
	remoteRelPath = pathpkg.Clean(filepath.ToSlash(strings.TrimSpace(remoteRelPath)))
	if remoteRelPath == "" || remoteRelPath == "." || pathpkg.IsAbs(remoteRelPath) || remoteRelPath == ".." || strings.HasPrefix(remoteRelPath, "../") {
		return fmt.Errorf("remote home path is invalid")
	}
	pathScript := factorySandboxRemoteHomePathScript(pathpkg.Dir(remoteRelPath), remoteRelPath, factorySandboxRemoteTempBase(remoteRelPath, content))
	if encoded == "" {
		script := pathScript + "\n" + factorySandboxRemoteBeginCopyScript() + "\n" + factorySandboxRemoteFinalizeCopyScript(mode)
		if err := deps.runProviderScript(ctx, provider, connectInfo, script, out); err != nil {
			return err
		}
		return nil
	}
	for offset := 0; offset < len(encoded); offset += factorySandboxCopyInputChunkEncodedBytes {
		end := offset + factorySandboxCopyInputChunkEncodedBytes
		if end > len(encoded) {
			end = len(encoded)
		}
		copyScript := factorySandboxRemoteContinueCopyScript()
		if offset == 0 {
			copyScript = factorySandboxRemoteBeginCopyScript()
		}
		script := pathScript + "\n" + copyScript + "\nprintf %s " + shellQuote(encoded[offset:end]) + " | base64 -d >> \"$remote_tmp\""
		if err := deps.runProviderScript(ctx, provider, connectInfo, script, out); err != nil {
			return err
		}
	}
	if err := deps.runProviderScript(ctx, provider, connectInfo, pathScript+"\n"+factorySandboxRemoteFinalizeCopyScript(mode), out); err != nil {
		return err
	}
	return nil
}

func factorySandboxRemoteAbsolutePathScript(remoteDir, remoteFile, remoteTmp string) string {
	return strings.Join([]string{
		"set -eu",
		"remote_dir=" + shellQuote(remoteDir),
		"remote_file=" + shellQuote(remoteFile),
		"remote_tmp=" + shellQuote(remoteTmp),
		factorySandboxRemotePathGuardScript(),
	}, "\n")
}

func factorySandboxRemoteHomePathScript(remoteDir, remoteFile, remoteTmpBase string) string {
	return strings.Join([]string{
		"set -eu",
		`remote_home="${HOME:-}"`,
		`if [ -z "$remote_home" ] && command -v getent >/dev/null 2>&1; then`,
		`  remote_home="$(getent passwd "$(id -u)" | cut -d: -f6)"`,
		`fi`,
		`if [ -z "$remote_home" ]; then remote_home="$(pwd)"; fi`,
		`remote_dir="$remote_home"/` + shellQuote(remoteDir),
		`remote_file="$remote_home"/` + shellQuote(remoteFile),
		`remote_tmp="$remote_dir"/` + shellQuote(remoteTmpBase),
		factorySandboxRemotePathGuardScript(),
	}, "\n")
}

func factorySandboxRemotePathGuardScript() string {
	return strings.Join([]string{
		`validate_remote_parent_no_symlink() {`,
		`  target_dir="$1"`,
		`  case "$target_dir" in /*) ;; *) echo "remote parent must be absolute: $target_dir" >&2; exit 1 ;; esac`,
		`  probe="/"`,
		`  rest="${target_dir#/}"`,
		`  old_ifs="$IFS"`,
		`  IFS="/"`,
		`  set -- $rest`,
		`  IFS="$old_ifs"`,
		`  for component do`,
		`    [ -z "$component" ] && continue`,
		`    if [ "$probe" = "/" ]; then probe="/$component"; else probe="$probe/$component"; fi`,
		`    if [ -L "$probe" ]; then echo "refusing symlink parent: $probe" >&2; exit 1; fi`,
		`    if [ ! -e "$probe" ]; then mkdir "$probe"; fi`,
		`    if [ ! -d "$probe" ]; then echo "remote parent is not a directory: $probe" >&2; exit 1; fi`,
		`  done`,
		`}`,
		`validate_remote_parent_no_symlink "$remote_dir"`,
		`if [ -L "$remote_file" ]; then echo "refusing symlink destination: $remote_file" >&2; exit 1; fi`,
	}, "\n")
}

func factorySandboxRemoteBeginCopyScript() string {
	return strings.Join([]string{
		`if [ -e "$remote_tmp" ] || [ -L "$remote_tmp" ]; then rm -f "$remote_tmp"; fi`,
		`( set -C; : > "$remote_tmp" ) || { echo "could not create remote temp file: $remote_tmp" >&2; exit 1; }`,
	}, "\n")
}

func factorySandboxRemoteContinueCopyScript() string {
	return `if [ -L "$remote_tmp" ] || [ ! -f "$remote_tmp" ]; then echo "remote temp file is not regular: $remote_tmp" >&2; exit 1; fi`
}

func factorySandboxRemoteFinalizeCopyScript(mode string) string {
	lines := []string{factorySandboxRemoteContinueCopyScript()}
	if strings.TrimSpace(mode) != "" {
		lines = append(lines, "chmod "+shellQuote(mode)+" \"$remote_tmp\"")
	}
	lines = append(lines, `mv -f "$remote_tmp" "$remote_file"`)
	return strings.Join(lines, "\n")
}

func factorySandboxRemoteTempPath(remoteDir, remoteFile string, content []byte) string {
	return pathpkg.Join(remoteDir, factorySandboxRemoteTempBase(remoteFile, content))
}

func factorySandboxRemoteTempBase(remoteFile string, content []byte) string {
	base := pathpkg.Base(filepath.ToSlash(strings.TrimSpace(remoteFile)))
	if base == "" || base == "." || base == "/" {
		base = "copy"
	}
	sum := sha256.Sum256(append(append([]byte(filepath.ToSlash(remoteFile)), 0), content...))
	return "." + base + ".hal-copy-" + hex.EncodeToString(sum[:])[:16] + ".tmp"
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
	script := factorySandboxRemoteAutoScript(req)
	workspaceDir := factorySandboxRemoteWorkspaceDir(record)
	if workspaceDir == "" {
		return []string{"sh", "-c", script}
	}
	return []string{"sh", "-c", "set -eu\ncd " + shellQuote(workspaceDir) + "\n" + script}
}

func factorySandboxRemoteWorkspaceDir(record factory.RunRecord) string {
	if name := repositoryNameFromRemote(record.RepoRemote); name != "" {
		return factorySandboxRemoteWorkspaceRoot + "/" + factorySandboxWorkspaceName(name, record.RepoRemote)
	}
	if repoPath := strings.TrimSpace(record.RepoPath); strings.HasPrefix(repoPath, "/workspace/") {
		return repoPath
	}
	if repoPath := strings.TrimSpace(record.RepoPath); strings.HasPrefix(repoPath, factorySandboxRemoteWorkspaceRoot+"/") {
		return repoPath
	}
	return ""
}

func repositoryNameFromRemote(remote string) string {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return ""
	}
	if strings.Contains(remote, "://") {
		if parsed, err := url.Parse(remote); err == nil && parsed.Scheme != "" {
			name := pathpkg.Base(strings.TrimSuffix(parsed.Path, "/"))
			if name == "." || name == "/" {
				return ""
			}
			return strings.TrimSpace(strings.TrimSuffix(name, ".git"))
		}
	}
	if idx := strings.IndexAny(remote, "?#"); idx >= 0 {
		remote = remote[:idx]
	}
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

func factorySandboxWorkspaceName(repoName string, remote string) string {
	name := safeFactorySandboxWorkspaceSegment(repoName)
	if identity := canonicalFactorySandboxRemoteIdentity(remote); identity != "" {
		sum := sha256.Sum256([]byte(identity))
		name += "-" + hex.EncodeToString(sum[:])[:12]
	}
	return name
}

func safeFactorySandboxWorkspaceSegment(value string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(value) {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	segment := strings.Trim(b.String(), ".-")
	if segment == "" {
		return "repo"
	}
	return segment
}

func factorySandboxRemoteMatches(expectedRemote string, actualRemoteOutput string) bool {
	expected := canonicalFactorySandboxRemoteIdentity(expectedRemote)
	actual := canonicalFactorySandboxRemoteIdentity(firstFactorySandboxOutputLine(actualRemoteOutput))
	if expected == "" || actual == "" {
		return strings.TrimSpace(expectedRemote) == strings.TrimSpace(firstFactorySandboxOutputLine(actualRemoteOutput))
	}
	return expected == actual
}

func firstFactorySandboxOutputLine(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) != "" {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

func canonicalFactorySandboxRemoteIdentity(remote string) string {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return ""
	}
	if idx := strings.IndexAny(remote, "?#"); idx >= 0 {
		remote = remote[:idx]
	}
	if strings.Contains(remote, "://") {
		if parsed, err := url.Parse(remote); err == nil && parsed.Scheme != "" {
			return canonicalFactorySandboxRemoteParts(parsed.Host, parsed.Path)
		}
	}
	if idx := strings.Index(remote, "://"); idx < 0 {
		if colon := strings.Index(remote, ":"); colon >= 0 {
			host := remote[:colon]
			if at := strings.LastIndex(host, "@"); at >= 0 {
				host = host[at+1:]
			}
			if !strings.Contains(host, "/") {
				return canonicalFactorySandboxRemoteParts(host, remote[colon+1:])
			}
		}
	}
	return canonicalFactorySandboxRemoteParts("", remote)
}

func canonicalFactorySandboxRemoteParts(host string, remotePath string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	remotePath = strings.TrimSpace(remotePath)
	remotePath = strings.TrimSuffix(strings.Trim(remotePath, "/"), ".git")
	if remotePath == "" || remotePath == "." {
		return ""
	}
	if cleaned := pathpkg.Clean("/" + remotePath); cleaned != "/" && cleaned != "." {
		remotePath = strings.TrimPrefix(cleaned, "/")
	}
	if host == "" {
		return remotePath
	}
	return host + "/" + remotePath
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

func recordFactorySandboxFailure(store factory.Store, deps factorySandboxExecutorDeps, record *factory.RunRecord, target *sandbox.SandboxState, step string, failureErr error, secretRedactor factory.RunSecretRedactor) error {
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
	message := factorySandboxSanitizedError(target, failureErr, secretRedactor)
	failure := factory.FailureSummary{
		Step:             step,
		Category:         factory.FailureCategorySandbox,
		Message:          message,
		Recoverable:      true,
		SuggestedCommand: factorySandboxFailureSuggestedCommand(record),
	}
	record.Failure = &failure
	if err := saveFactorySandboxRunRecordWithRedactor(store, deps, record, secretRedactor); err != nil {
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

func recordFactorySandboxCleanedUp(store factory.Store, deps factorySandboxExecutorDeps, record *factory.RunRecord, target *sandbox.SandboxState, secretRedactor factory.RunSecretRedactor) error {
	if record == nil || strings.TrimSpace(record.RunID) == "" {
		return nil
	}
	if deps.now == nil {
		deps.now = defaultFactorySandboxExecutorDeps.now
	}
	if deps.saveRun == nil {
		deps.saveRun = defaultFactorySandboxExecutorDeps.saveRun
	}
	stored, err := store.LoadRun(record.RunID)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("load factory sandbox run for cleanup metadata: %w", err)
		}
		stored = record
	}
	stored.SandboxName, stored.Sandbox = factorySandboxCleanedMetadata(*stored, target)
	if stored.Failure != nil {
		stored.Failure.SuggestedCommand = factoryRunInspectCommand(stored.RunID)
	}
	stored.UpdatedAt = deps.now().UTC()
	safeRecord := redactFactoryRunRecordForStorage(*stored, secretRedactor)
	if err := deps.saveRun(store, &safeRecord); err != nil {
		return fmt.Errorf("record factory sandbox cleanup metadata: %w", err)
	}
	*record = safeRecord
	return nil
}

func factorySandboxCleanedMetadata(record factory.RunRecord, target *sandbox.SandboxState) (string, *factory.SandboxMetadata) {
	name := strings.TrimSpace(record.SandboxName)
	metadata := &factory.SandboxMetadata{}
	if record.Sandbox != nil {
		*metadata = *record.Sandbox
		if strings.TrimSpace(metadata.Name) != "" {
			name = strings.TrimSpace(metadata.Name)
		}
	}
	if target != nil {
		if name == "" {
			name = strings.TrimSpace(target.Name)
		}
		if metadata.Name == "" {
			metadata.Name = strings.TrimSpace(target.Name)
		}
		if metadata.Provider == "" {
			metadata.Provider = strings.TrimSpace(target.Provider)
		}
		if metadata.Size == "" {
			metadata.Size = strings.TrimSpace(target.Size)
		}
	}
	if name == "" {
		name = strings.TrimSpace(metadata.Name)
	}
	if name == "" {
		return "", nil
	}
	metadata.Name = name
	metadata.Status = sandbox.StatusUnknown
	metadata.Connection = nil
	metadata.SSHCommand = ""
	metadata.CleanupCommand = ""
	metadata.Handoff = ""
	return name, metadata
}

func factorySandboxSanitizedError(target *sandbox.SandboxState, err error, secretRedactor factory.RunSecretRedactor) string {
	if err == nil {
		return "sandbox factory executor failed"
	}
	message := strings.TrimSpace(err.Error())
	if message == "" {
		message = "sandbox factory executor failed"
	}
	if target == nil {
		return sanitizeCredentialedRemoteReferences(secretRedactor.RedactString(message))
	}
	redactor := sandboxRedactor(false, nil, target)
	return sanitizeCredentialedRemoteReferences(secretRedactor.RedactString(redactor.Redact(message)))
}

func factorySandboxRecordedError(prefix string, target *sandbox.SandboxState, err error, secretRedactor factory.RunSecretRedactor) error {
	return fmt.Errorf("%s: %s", prefix, factorySandboxSanitizedError(target, err, secretRedactor))
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
		Size:           instance.Size,
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
	cmd, err := provider.Exec(info, factorySandboxProviderExecArgs(args))
	if err != nil {
		return err
	}
	if cmd == nil {
		return fmt.Errorf("sandbox provider returned nil exec command")
	}
	return sandbox.RunCmdContext(ctx, cmd, out)
}

func runFactorySandboxProviderExecIO(ctx context.Context, provider sandbox.Provider, info *sandbox.ConnectInfo, args []string, stdout, stderr io.Writer) error {
	if provider == nil {
		return fmt.Errorf("sandbox provider is required")
	}
	cmd, err := provider.Exec(info, factorySandboxProviderExecArgs(args))
	if err != nil {
		return err
	}
	if cmd == nil {
		return fmt.Errorf("sandbox provider returned nil exec command")
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return runFactorySandboxArtifactCommand(ctx, cmd)
}

func factorySandboxProviderExecArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}
	return []string{"sh", "-c", shellCommand(args)}
}

func runFactorySandboxProviderScript(ctx context.Context, provider sandbox.Provider, info *sandbox.ConnectInfo, script string, out io.Writer) error {
	if provider == nil {
		return fmt.Errorf("sandbox provider is required")
	}
	if _, ok := provider.(*sandbox.DaytonaProvider); ok {
		cmd, err := provider.Exec(info, []string{"sh", "-c", script})
		if err != nil {
			return err
		}
		if cmd == nil {
			return fmt.Errorf("sandbox provider returned nil exec command")
		}
		return sandbox.RunCmdContext(ctx, cmd, out)
	}
	cmd, err := provider.Exec(info, []string{"sh", "-s"})
	if err != nil {
		return err
	}
	if cmd == nil {
		return fmt.Errorf("sandbox provider returned nil exec command")
	}
	cmd.Stdin = strings.NewReader(script)
	return sandbox.RunCmdContext(ctx, cmd, out)
}

func runFactorySandboxProviderExecWithEnv(ctx context.Context, provider sandbox.Provider, info *sandbox.ConnectInfo, args []string, env map[string]string, out io.Writer) error {
	script, err := factorySandboxEnvExecScript(args, env)
	if err != nil {
		return err
	}
	return runFactorySandboxProviderScript(ctx, provider, info, script, out)
}

func factorySandboxEnvExecScript(args []string, env map[string]string) (string, error) {
	var script strings.Builder
	script.WriteString("set -e\n")
	for _, key := range sortedStringMapKeys(env) {
		if strings.TrimSpace(env[key]) == "" {
			continue
		}
		if !isShellIdentifier(key) {
			return "", fmt.Errorf("invalid sandbox environment variable name %q", key)
		}
		script.WriteString("export ")
		script.WriteString(key)
		script.WriteString("=")
		script.WriteString(shellQuote(env[key]))
		script.WriteString("\n")
	}
	script.WriteString("exec ")
	script.WriteString(shellCommand(args))
	script.WriteString("\n")
	return script.String(), nil
}

func factorySandboxSortedEnvAssignments(env map[string]string) []string {
	if len(env) == 0 {
		return nil
	}
	keys := sortedStringMapKeys(env)
	assignments := make([]string, 0, len(keys))
	for _, key := range keys {
		if strings.TrimSpace(env[key]) == "" {
			continue
		}
		assignments = append(assignments, key+"="+env[key])
	}
	return assignments
}

func isShellIdentifier(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		ch := name[i]
		if i == 0 {
			if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || ch == '_' {
				continue
			}
			return false
		}
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' {
			continue
		}
		return false
	}
	return true
}

func saveFactorySandboxRunRecord(store factory.Store, record *factory.RunRecord) error {
	return store.SaveRun(record)
}

func saveFactorySandboxRunRecordWithRedactor(store factory.Store, deps factorySandboxExecutorDeps, record *factory.RunRecord, redactor factory.RunSecretRedactor) error {
	if record == nil {
		return deps.saveRun(store, record)
	}
	safeRecord := redactFactoryRunRecordForStorage(*record, redactor)
	return deps.saveRun(store, &safeRecord)
}

func redactFactorySandboxProvisionRepo(record factory.RunRecord, redactor factory.RunSecretRedactor) string {
	return redactFactoryRunRecordForStorage(record, redactor).RepoRemote
}

func appendFactorySandboxTimelineEvent(store factory.Store, event *factory.EventRecord) error {
	return store.AppendEvent(event)
}

func appendFactorySandboxLogChunk(store factory.Store, chunk *factory.LogChunk) error {
	return store.AppendLogChunk(chunk)
}
