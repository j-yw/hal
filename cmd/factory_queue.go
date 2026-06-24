package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/spf13/cobra"
)

var factoryQueueAddJSONFlag bool
var factoryQueueListJSONFlag bool
var factoryQueueWorkJSONFlag bool

type factoryQueueAddDeps struct {
	defaultStore func() (factory.Store, error)
	now          func() time.Time
	newQueueID   func() (string, error)
}

type factoryQueueListDeps struct {
	defaultStore func() (factory.Store, error)
}

type factoryQueueWorkDeps struct {
	defaultStore    func() (factory.Store, error)
	now             func() time.Time
	claim           *factory.QueueClaim
	currentBranch   func(string) (string, error)
	runPipeline     func(context.Context, factoryRunPipelineRequest) error
	runSandbox      func(context.Context, factorySandboxExecutorRequest) error
	sandboxCopier   factory.SandboxArtifactCopier
	sandboxRequests func(string, factory.RunRecord) []factory.SandboxArtifactRequest
}

type factoryQueueAddRequest struct {
	RunID        string
	ExecutorMode string
	JSON         bool
}

type factoryQueueListRequest struct {
	JSON bool
}

type factoryQueueWorkRequest struct {
	JSON bool
}

var defaultFactoryQueueAddDeps = factoryQueueAddDeps{
	defaultStore: factory.DefaultStore,
	now:          time.Now,
}

var defaultFactoryQueueListDeps = factoryQueueListDeps{
	defaultStore: factory.DefaultStore,
}

var defaultFactoryQueueWorkDeps = factoryQueueWorkDeps{
	defaultStore:    factory.DefaultStore,
	now:             time.Now,
	currentBranch:   defaultFactoryRunDeps.currentBranch,
	runPipeline:     runFactoryRunPipeline,
	runSandbox:      defaultFactoryRunDeps.runSandbox,
	sandboxRequests: defaultFactorySandboxArtifactRequests,
}

var factoryQueueCmd = &cobra.Command{
	Use:   "queue",
	Short: "Manage queued factory work",
	Long: `Manage queued factory work stored in the global factory queue.

Queue commands enqueue existing factory runs, list durable queue entries, and
claim one queued run for bounded local worker processing. Queue state is stored
in the global factory store so pending work survives CLI exits and restarts.`,
	Example: `  hal factory queue add run-20260620-001 local
  hal factory queue list --json
  hal factory queue work --json`,
}

var factoryQueueAddCmd = &cobra.Command{
	Use:   "add <run-id> <executor-mode>",
	Short: "Add a factory run to the queue",
	Args:  validateFactoryQueueAddArgs,
	Long: `Add an existing factory run to the durable factory queue.

Provide the run ID to enqueue and the executor mode that the worker should use
when processing it. Use --json for machine-readable output following the
factory-queue-add-v1 contract.`,
	Example: `  hal factory queue add run-20260620-001 local
  hal factory queue add run-20260620-001 local --json`,
	RunE: runFactoryQueueAdd,
}

var factoryQueueListCmd = &cobra.Command{
	Use:   "list",
	Short: "List factory queue entries",
	Args:  noArgsValidation(),
	Long: `List durable factory queue entries from the global factory store.

Use --json for machine-readable output following the factory-queue-list-v1
contract. JSON output is intended for automation that needs deterministic queue
ordering and inspectable queued, claimed, and failed entries.`,
	Example: `  hal factory queue list
  hal factory queue list --json`,
	RunE: runFactoryQueueList,
}

var factoryQueueWorkCmd = &cobra.Command{
	Use:   "work",
	Short: "Claim and process one queued factory run",
	Args:  noArgsValidation(),
	Long: `Claim and process at most one queued factory run.

Queue work uses the durable factory queue to atomically claim a pending entry
before running it through the local factory executor. Use --json for
machine-readable output following the factory-queue-work-v1 contract, including
the no-work response when no queued entries are available.`,
	Example: `  hal factory queue work
  hal factory queue work --json`,
	RunE: runFactoryQueueWork,
}

func configureFactoryQueueCommands() {
	factoryQueueAddCmd.Flags().BoolVar(&factoryQueueAddJSONFlag, "json", false, "Output machine-readable JSON (factory-queue-add-v1 contract)")
	factoryQueueListCmd.Flags().BoolVar(&factoryQueueListJSONFlag, "json", false, "Output machine-readable JSON (factory-queue-list-v1 contract)")
	factoryQueueWorkCmd.Flags().BoolVar(&factoryQueueWorkJSONFlag, "json", false, "Output machine-readable JSON (factory-queue-work-v1 contract)")
	factoryQueueCmd.AddCommand(factoryQueueAddCmd)
	factoryQueueCmd.AddCommand(factoryQueueListCmd)
	factoryQueueCmd.AddCommand(factoryQueueWorkCmd)
}

func runFactoryQueueAdd(cmd *cobra.Command, args []string) error {
	req, err := factoryQueueAddRequestFromCommand(cmd, args)
	if err != nil {
		return err
	}

	out := io.Writer(os.Stdout)
	if cmd != nil {
		out = cmd.OutOrStdout()
	}

	return runFactoryQueueAddWithDeps(out, req, defaultFactoryQueueAddDeps)
}

func runFactoryQueueList(cmd *cobra.Command, _ []string) error {
	req, err := factoryQueueListRequestFromCommand(cmd)
	if err != nil {
		return err
	}

	out := io.Writer(os.Stdout)
	if cmd != nil {
		out = cmd.OutOrStdout()
	}

	return runFactoryQueueListWithDeps(out, req, defaultFactoryQueueListDeps)
}

func runFactoryQueueWork(cmd *cobra.Command, _ []string) error {
	req, err := factoryQueueWorkRequestFromCommand(cmd)
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

	return runFactoryQueueWorkWithDeps(ctx, out, req, defaultFactoryQueueWorkDeps)
}

func validateFactoryQueueAddArgs(cmd *cobra.Command, args []string) error {
	switch {
	case len(args) == 0:
		return exitWithCode(cmd, ExitCodeValidation, fmt.Errorf("factory run ID is required"))
	case len(args) == 1:
		return exitWithCode(cmd, ExitCodeValidation, fmt.Errorf("factory executor mode is required"))
	case len(args) > 2:
		return exitWithCode(cmd, ExitCodeValidation, fmt.Errorf("accepts 2 arg(s), received %d", len(args)))
	default:
		return nil
	}
}

func factoryQueueAddRequestFromCommand(cmd *cobra.Command, args []string) (factoryQueueAddRequest, error) {
	if err := validateFactoryQueueAddArgs(cmd, args); err != nil {
		return factoryQueueAddRequest{}, err
	}

	jsonMode := factoryQueueAddJSONFlag
	if cmd != nil && cmd.Flags().Lookup("json") != nil {
		value, err := cmd.Flags().GetBool("json")
		if err != nil {
			return factoryQueueAddRequest{}, err
		}
		jsonMode = value
	}

	return factoryQueueAddRequest{
		RunID:        args[0],
		ExecutorMode: args[1],
		JSON:         jsonMode,
	}, nil
}

func factoryQueueListRequestFromCommand(cmd *cobra.Command) (factoryQueueListRequest, error) {
	jsonMode := factoryQueueListJSONFlag
	if cmd != nil && cmd.Flags().Lookup("json") != nil {
		value, err := cmd.Flags().GetBool("json")
		if err != nil {
			return factoryQueueListRequest{}, err
		}
		jsonMode = value
	}

	return factoryQueueListRequest{JSON: jsonMode}, nil
}

func factoryQueueWorkRequestFromCommand(cmd *cobra.Command) (factoryQueueWorkRequest, error) {
	jsonMode := factoryQueueWorkJSONFlag
	if cmd != nil && cmd.Flags().Lookup("json") != nil {
		value, err := cmd.Flags().GetBool("json")
		if err != nil {
			return factoryQueueWorkRequest{}, err
		}
		jsonMode = value
	}

	return factoryQueueWorkRequest{JSON: jsonMode}, nil
}

func runFactoryQueueAddWithDeps(out io.Writer, req factoryQueueAddRequest, deps factoryQueueAddDeps) error {
	if out == nil {
		out = io.Discard
	}
	deps = normalizeFactoryQueueAddDeps(deps)
	if deps.defaultStore == nil {
		return fmt.Errorf("factory store dependency is required")
	}

	executorMode, err := factory.ValidateExecutorMode(req.ExecutorMode)
	if err != nil {
		return err
	}

	store, err := deps.defaultStore()
	if err != nil {
		return fmt.Errorf("open factory store: %w", err)
	}
	record, err := store.LoadRun(req.RunID)
	if err != nil {
		return fmt.Errorf("load factory run %q: %w", strings.TrimSpace(req.RunID), err)
	}
	if record.Status != factory.RunStatusPending {
		return fmt.Errorf("factory run %q is %q, want %q", record.RunID, record.Status, factory.RunStatusPending)
	}
	if err := validateFactoryQueueExecutorRun(*record, executorMode); err != nil {
		return err
	}

	entry, err := store.EnqueueQueueEntryWithLockedPostSave(req.RunID, executorMode, factory.QueueOperationOptions{
		Now:        deps.now,
		NewQueueID: deps.newQueueID,
	}, func(entry factory.QueueEntry) error {
		return recordFactoryRunQueued(store, entry, deps.now())
	})
	if err != nil {
		return fmt.Errorf("enqueue factory run %q: %w", strings.TrimSpace(req.RunID), err)
	}

	return renderFactoryQueueAddResult(out, entry, req.JSON)
}

func runFactoryQueueListWithDeps(out io.Writer, req factoryQueueListRequest, deps factoryQueueListDeps) error {
	if out == nil {
		out = io.Discard
	}
	deps = normalizeFactoryQueueListDeps(deps)
	if deps.defaultStore == nil {
		return fmt.Errorf("factory store dependency is required")
	}

	store, err := deps.defaultStore()
	if err != nil {
		return fmt.Errorf("open factory store: %w", err)
	}

	entries, err := store.ListQueue()
	if err != nil {
		return fmt.Errorf("list factory queue: %w", err)
	}

	return renderFactoryQueueListResult(out, entries, req.JSON)
}

func runFactoryQueueWorkWithDeps(ctx context.Context, out io.Writer, req factoryQueueWorkRequest, deps factoryQueueWorkDeps) error {
	if out == nil {
		out = io.Discard
	}
	deps = normalizeFactoryQueueWorkDeps(deps)
	if deps.defaultStore == nil {
		return fmt.Errorf("factory store dependency is required")
	}
	if deps.runPipeline == nil {
		return fmt.Errorf("factory run pipeline dependency is required")
	}

	store, err := deps.defaultStore()
	if err != nil {
		return fmt.Errorf("open factory store: %w", err)
	}

	entry, err := store.ClaimNextQueueEntry(factory.QueueOperationOptions{
		Now:   deps.now,
		Claim: deps.claim,
	})
	if err != nil {
		return fmt.Errorf("claim factory queue work: %w", err)
	}
	if entry != nil {
		claimedAt := deps.now()
		if entry.ClaimedAt != nil {
			claimedAt = *entry.ClaimedAt
		}
		if err := recordFactoryRunClaimed(store, *entry, claimedAt); err != nil {
			finalEntry, finalErr := failClaimedFactoryQueueEntryAfterClaimError(store, *entry, err, deps.now)
			if finalErr == nil {
				entry = &finalEntry
				return renderFactoryQueueWorkResult(out, entry, req.JSON)
			}
			if renderErr := renderFactoryQueueWorkResult(out, &finalEntry, req.JSON); renderErr != nil {
				return errors.Join(finalErr, renderErr)
			}
			return finalErr
		}
		finalEntry, err := executeClaimedFactoryQueueEntry(ctx, store, *entry, deps)
		if err != nil {
			if renderErr := renderFactoryQueueWorkResult(out, &finalEntry, req.JSON); renderErr != nil {
				return errors.Join(err, renderErr)
			}
			return err
		}
		entry = &finalEntry
	}

	return renderFactoryQueueWorkResult(out, entry, req.JSON)
}

func executeClaimedFactoryQueueEntry(ctx context.Context, store factory.Store, entry factory.QueueEntry, deps factoryQueueWorkDeps) (factory.QueueEntry, error) {
	record, loadErr := store.LoadRun(entry.RunID)
	if _, err := factory.ValidateExecutorMode(entry.ExecutorMode); err != nil {
		if loadErr != nil {
			return failClaimedFactoryQueueEntry(store, entry, err, deps.now)
		}
		return failClaimedFactoryQueueEntryAndRun(store, entry, *record, err, deps.now)
	}

	if loadErr != nil {
		return failClaimedFactoryQueueEntry(store, entry, fmt.Errorf("load claimed factory run %q: %w", entry.RunID, loadErr), deps.now)
	}
	if err := validateClaimedFactoryRun(*record); err != nil {
		return failClaimedFactoryQueueEntryAfterRunStateError(store, entry, *record, err, deps.now)
	}
	record.ExecutorMode = entry.ExecutorMode
	if err := validateFactoryQueueExecutorRun(*record, entry.ExecutorMode); err != nil {
		return failClaimedFactoryQueueEntryAndRun(store, entry, *record, err, deps.now)
	}

	currentBranch := deps.currentBranch
	if currentBranch == nil {
		currentBranch = defaultFactoryRunDeps.currentBranch
	}
	runDir, err := factoryQueueRunDir(*record)
	if err != nil {
		return failClaimedFactoryQueueEntryAndRun(store, entry, *record, err, deps.now)
	}
	if entry.ExecutorMode != factory.ExecutorModeSandbox {
		if err := validateClaimedFactoryQueueBranch(runDir, *record, currentBranch); err != nil {
			return failClaimedFactoryQueueEntryAndRun(store, entry, *record, err, deps.now)
		}
	}

	result, execErr := executeFactoryRun(ctx, runDir, factoryRunRequestFromQueueRecord(*record), store, *record, io.Discard, "", factoryRunExecutionDeps{
		now:             deps.now,
		currentBranch:   currentBranch,
		runPipeline:     deps.runPipeline,
		runSandbox:      deps.runSandbox,
		sandboxCopier:   deps.sandboxCopier,
		sandboxRequests: deps.sandboxRequests,
	})
	if execErr != nil {
		return finalizeClaimedFactoryQueueExecutionError(store, entry, result.Record, execErr, deps.now)
	}

	return succeedClaimedFactoryQueueEntry(store, entry, deps.now)
}

func validateFactoryQueueExecutorRun(record factory.RunRecord, executorMode string) error {
	if strings.TrimSpace(executorMode) == factory.ExecutorModeSandbox && strings.TrimSpace(record.BaseBranch) == "" {
		return fmt.Errorf("sandbox factory run %q requires a base branch", record.RunID)
	}
	return nil
}

func validateClaimedFactoryQueueBranch(dir string, record factory.RunRecord, currentBranch func(string) (string, error)) error {
	wantBranch := strings.TrimSpace(record.BranchName)
	if wantBranch == "" {
		return nil
	}
	if currentBranch == nil {
		currentBranch = defaultFactoryRunDeps.currentBranch
	}
	gotBranch, err := currentBranch(dir)
	if err != nil {
		return fmt.Errorf("resolve queued factory run branch: %w", err)
	}
	gotBranch = strings.TrimSpace(gotBranch)
	if gotBranch == "" {
		return fmt.Errorf("queued factory run %q branch is unavailable; want %q", record.RunID, wantBranch)
	}
	if gotBranch != wantBranch {
		return fmt.Errorf("queued factory run %q is on branch %q, want %q", record.RunID, gotBranch, wantBranch)
	}
	return nil
}

func finalizeClaimedFactoryQueueExecutionError(store factory.Store, entry factory.QueueEntry, record factory.RunRecord, cause error, now func() time.Time) (factory.QueueEntry, error) {
	latest := record
	if strings.TrimSpace(record.RunID) != "" {
		if loaded, err := store.LoadRun(record.RunID); err == nil && loaded != nil {
			latest = *loaded
		}
	}

	switch latest.Status {
	case factory.RunStatusSucceeded:
		completedEntry, markErr := succeedClaimedFactoryQueueEntry(store, entry, now)
		if markErr != nil {
			return entry, errors.Join(cause, markErr)
		}
		return completedEntry, cause
	case factory.RunStatusFailed:
		return failClaimedFactoryQueueEntryWithRunEvent(store, entry, latest.RunID, cause, now)
	default:
		if strings.TrimSpace(latest.RunID) == "" {
			return failClaimedFactoryQueueEntry(store, entry, cause, now)
		}
		return failClaimedFactoryQueueEntryAndRun(store, entry, latest, cause, now)
	}
}

func succeedClaimedFactoryQueueEntry(store factory.Store, entry factory.QueueEntry, now func() time.Time) (factory.QueueEntry, error) {
	completedAt := now()
	completedEntry, err := store.MarkQueueEntrySucceeded(entry.QueueID, factory.QueueOperationOptions{
		Now:                  func() time.Time { return completedAt },
		ExpectedClaimedAt:    entry.ClaimedAt,
		ExpectedAttemptCount: entry.AttemptCount,
	})
	if err != nil {
		return entry, err
	}
	if eventErr := recordFactoryRunQueueSucceeded(store, entry.RunID, completedAt, completedEntry); eventErr != nil {
		return completedEntry, fmt.Errorf("record factory queue success event: %w", eventErr)
	}
	return completedEntry, nil
}

func failClaimedFactoryQueueEntry(store factory.Store, entry factory.QueueEntry, cause error, now func() time.Time) (factory.QueueEntry, error) {
	if cause == nil {
		cause = fmt.Errorf("factory queue work failed")
	}
	failedEntry, markErr := store.MarkQueueEntryFailed(entry.QueueID, cause.Error(), factory.QueueOperationOptions{
		Now:                  now,
		ExpectedClaimedAt:    entry.ClaimedAt,
		ExpectedAttemptCount: entry.AttemptCount,
	})
	if markErr != nil {
		return entry, errors.Join(cause, markErr)
	}
	return failedEntry, cause
}

func failClaimedFactoryQueueEntryWithRunEvent(store factory.Store, entry factory.QueueEntry, runID string, cause error, now func() time.Time) (factory.QueueEntry, error) {
	if cause == nil {
		cause = fmt.Errorf("factory queue work failed")
	}
	failedAt := now()
	failedEntry, markErr := store.MarkQueueEntryFailed(entry.QueueID, cause.Error(), factory.QueueOperationOptions{
		Now:                  func() time.Time { return failedAt },
		ExpectedClaimedAt:    entry.ClaimedAt,
		ExpectedAttemptCount: entry.AttemptCount,
	})
	if markErr != nil {
		return entry, errors.Join(cause, markErr)
	}
	if strings.TrimSpace(runID) == "" {
		runID = entry.RunID
	}
	if eventErr := recordFactoryRunQueueFailed(store, runID, failedAt, failedEntry, cause); eventErr != nil {
		return failedEntry, errors.Join(cause, fmt.Errorf("record factory queue failure event: %w", eventErr))
	}
	return failedEntry, cause
}

func requeueClaimedFactoryQueueEntry(store factory.Store, entry factory.QueueEntry, cause error, now func() time.Time) (factory.QueueEntry, error) {
	if cause == nil {
		cause = fmt.Errorf("factory queue claim bookkeeping failed")
	}
	requeuedEntry, requeueErr := store.RequeueClaimedQueueEntry(entry.QueueID, cause.Error(), factory.QueueOperationOptions{
		Now:                  now,
		ExpectedClaimedAt:    entry.ClaimedAt,
		ExpectedAttemptCount: entry.AttemptCount,
	})
	if requeueErr != nil {
		return entry, errors.Join(cause, requeueErr)
	}
	return requeuedEntry, cause
}

func failClaimedFactoryQueueEntryAfterClaimError(store factory.Store, entry factory.QueueEntry, cause error, now func() time.Time) (factory.QueueEntry, error) {
	record, err := store.LoadRun(entry.RunID)
	if err != nil {
		return failClaimedFactoryQueueEntry(store, entry, cause, now)
	}
	if record.Status == factory.RunStatusPending && strings.TrimSpace(record.CurrentStep) == factory.QueueStatusQueued {
		return requeueClaimedFactoryQueueEntry(store, entry, cause, now)
	}
	return failClaimedFactoryQueueEntryAfterRunStateError(store, entry, *record, cause, now)
}

func failClaimedFactoryQueueEntryAfterRunStateError(store factory.Store, entry factory.QueueEntry, record factory.RunRecord, cause error, now func() time.Time) (factory.QueueEntry, error) {
	switch record.Status {
	case factory.RunStatusSucceeded:
		return succeedClaimedFactoryQueueEntry(store, entry, now)
	case factory.RunStatusFailed, factory.RunStatusCanceled:
		return failClaimedFactoryQueueEntry(store, entry, terminalFactoryRunQueueError(record, cause), now)
	}
	if shouldFailReclaimedRunningFactoryRun(record, entry) {
		return failClaimedFactoryQueueEntryAndRun(store, entry, record, cause, now)
	}
	return failClaimedFactoryQueueEntry(store, entry, cause, now)
}

func terminalFactoryRunQueueError(record factory.RunRecord, fallback error) error {
	if record.Failure != nil {
		if message := strings.TrimSpace(record.Failure.Message); message != "" {
			return errors.New(message)
		}
	}
	if status := strings.TrimSpace(record.Status); status != "" {
		return fmt.Errorf("factory run %q is %q", record.RunID, status)
	}
	if fallback != nil {
		return fallback
	}
	return fmt.Errorf("factory run %q is terminal", record.RunID)
}

func shouldFailReclaimedRunningFactoryRun(record factory.RunRecord, entry factory.QueueEntry) bool {
	return entry.AttemptCount > 1 && record.Status == factory.RunStatusRunning
}

func failClaimedFactoryQueueEntryAndRun(store factory.Store, entry factory.QueueEntry, record factory.RunRecord, cause error, now func() time.Time) (factory.QueueEntry, error) {
	if cause == nil {
		cause = fmt.Errorf("factory queue work failed")
	}
	failedAt := now()
	failedEntry, markErr := store.MarkQueueEntryFailed(entry.QueueID, cause.Error(), factory.QueueOperationOptions{
		Now:                  func() time.Time { return failedAt },
		ExpectedClaimedAt:    entry.ClaimedAt,
		ExpectedAttemptCount: entry.AttemptCount,
	})
	if markErr != nil {
		return entry, errors.Join(cause, markErr)
	}

	failedRecord, recordErr := markFactoryRunFailed(store, record, failedAt, cause)
	if recordErr != nil {
		return failedEntry, errors.Join(cause, recordErr)
	}
	var eventErrs []error
	if eventErr := recordFactoryRunQueueFailed(store, failedRecord.RunID, failedAt, failedEntry, cause); eventErr != nil {
		eventErrs = append(eventErrs, fmt.Errorf("record factory queue failure event: %w", eventErr))
	}
	if failedRecord.Failure != nil {
		if eventErr := recordFactoryRunFailureClassified(store, failedRecord.RunID, failedAt, *failedRecord.Failure); eventErr != nil {
			eventErrs = append(eventErrs, fmt.Errorf("record factory failure classification event: %w", eventErr))
		}
	}
	if len(eventErrs) > 0 {
		return failedEntry, errors.Join(append([]error{cause}, eventErrs...)...)
	}
	return failedEntry, cause
}

func recordFactoryRunQueueFailed(store factory.Store, runID string, now time.Time, entry factory.QueueEntry, cause error) error {
	metadata := map[string]any{
		"queueId":      entry.QueueID,
		"executorMode": entry.ExecutorMode,
		"status":       factory.QueueStatusFailed,
		"step":         factory.QueueStatusClaimed,
		"error":        cause.Error(),
	}
	if entry.AttemptCount != 0 {
		metadata["attemptCount"] = entry.AttemptCount
	}
	return appendFactoryRunTimelineEvent(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypeStepEnded,
		Summary:   "Factory queue work failed",
		Metadata:  metadata,
	})
}

func recordFactoryRunQueueSucceeded(store factory.Store, runID string, now time.Time, entry factory.QueueEntry) error {
	metadata := map[string]any{
		"queueId":      entry.QueueID,
		"executorMode": entry.ExecutorMode,
		"status":       factory.QueueStatusSucceeded,
		"step":         factory.QueueStatusClaimed,
	}
	if entry.AttemptCount != 0 {
		metadata["attemptCount"] = entry.AttemptCount
	}
	return appendFactoryRunTimelineEvent(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypeStepEnded,
		Summary:   "Factory queue work succeeded",
		Metadata:  metadata,
	})
}

func factoryRunRequestFromQueueRecord(record factory.RunRecord) factoryRunRequest {
	req := factoryRunRequest{
		BaseBranch:  strings.TrimSpace(record.BaseBranch),
		Sandbox:     strings.TrimSpace(record.ExecutorMode) == factory.ExecutorModeSandbox,
		SandboxName: strings.TrimSpace(record.SandboxName),
	}
	switch record.Source.Kind {
	case factory.SourceKindMarkdown:
		req.MarkdownPath = strings.TrimSpace(record.Source.Path)
	case factory.SourceKindReport:
		req.ReportPath = strings.TrimSpace(record.Source.ReportPath)
		if req.ReportPath == "" {
			req.ReportPath = strings.TrimSpace(record.Source.Path)
		}
	}
	return req
}

func factoryQueueRunDir(record factory.RunRecord) (string, error) {
	if dir := strings.TrimSpace(record.RepoPath); dir != "" {
		if !filepath.IsAbs(dir) {
			return "", fmt.Errorf("queued factory run %q repository path %q is not absolute", record.RunID, dir)
		}
		return dir, nil
	}
	return "", fmt.Errorf("queued factory run %q repository path is unavailable", record.RunID)
}

func normalizeFactoryQueueAddDeps(deps factoryQueueAddDeps) factoryQueueAddDeps {
	if deps.defaultStore == nil {
		deps.defaultStore = defaultFactoryQueueAddDeps.defaultStore
	}
	if deps.now == nil {
		deps.now = defaultFactoryQueueAddDeps.now
	}
	return deps
}

func normalizeFactoryQueueListDeps(deps factoryQueueListDeps) factoryQueueListDeps {
	if deps.defaultStore == nil {
		deps.defaultStore = defaultFactoryQueueListDeps.defaultStore
	}
	return deps
}

func normalizeFactoryQueueWorkDeps(deps factoryQueueWorkDeps) factoryQueueWorkDeps {
	if deps.defaultStore == nil {
		deps.defaultStore = defaultFactoryQueueWorkDeps.defaultStore
	}
	if deps.now == nil {
		deps.now = defaultFactoryQueueWorkDeps.now
	}
	if deps.runPipeline == nil {
		deps.runPipeline = defaultFactoryQueueWorkDeps.runPipeline
	}
	if deps.runSandbox == nil {
		deps.runSandbox = defaultFactoryQueueWorkDeps.runSandbox
	}
	if deps.currentBranch == nil {
		deps.currentBranch = defaultFactoryQueueWorkDeps.currentBranch
	}
	if deps.sandboxRequests == nil {
		deps.sandboxRequests = defaultFactoryQueueWorkDeps.sandboxRequests
	}
	return deps
}

func recordFactoryRunQueued(store factory.Store, entry factory.QueueEntry, now time.Time) error {
	record, err := store.LoadRun(entry.RunID)
	if err != nil {
		return fmt.Errorf("load queued factory run %q: %w", entry.RunID, err)
	}
	if record.Status != factory.RunStatusPending {
		return fmt.Errorf("factory run %q is %q, want %q", record.RunID, record.Status, factory.RunStatusPending)
	}
	if currentStep := strings.TrimSpace(record.CurrentStep); currentStep != "" && currentStep != factory.RunStatusPending {
		return fmt.Errorf("factory run %q is at step %q, want %q", record.RunID, record.CurrentStep, factory.RunStatusPending)
	}

	previous := *record
	record.CurrentStep = factory.QueueStatusQueued
	record.UpdatedAt = now.UTC()
	if err := store.SaveRun(record); err != nil {
		return fmt.Errorf("record queued factory run %q: %w", entry.RunID, err)
	}

	if err := appendFactoryRunTimelineEvent(store, entry.RunID, now, factoryTimelineEvent{
		EventType: factory.EventTypeCommandOutputSummary,
		Summary:   "Factory run queued",
		Metadata: map[string]any{
			"queueId":      entry.QueueID,
			"executorMode": entry.ExecutorMode,
			"status":       factory.QueueStatusQueued,
		},
	}); err != nil {
		if restoreErr := store.SaveRun(&previous); restoreErr != nil {
			return errors.Join(err, fmt.Errorf("restore queued factory run %q: %w", entry.RunID, restoreErr))
		}
		return err
	}
	return nil
}

func recordFactoryRunClaimed(store factory.Store, entry factory.QueueEntry, now time.Time) error {
	record, err := store.LoadRun(entry.RunID)
	if err != nil {
		return fmt.Errorf("load claimed factory run %q: %w", entry.RunID, err)
	}
	if err := validateClaimableFactoryRun(*record, entry); err != nil {
		return err
	}

	previous := *record
	record.CurrentStep = factory.QueueStatusClaimed
	record.UpdatedAt = now.UTC()
	if err := store.SaveRun(record); err != nil {
		return fmt.Errorf("record claimed factory run %q: %w", entry.RunID, err)
	}

	metadata := map[string]any{
		"queueId":      entry.QueueID,
		"executorMode": entry.ExecutorMode,
		"status":       factory.QueueStatusClaimed,
		"attemptCount": entry.AttemptCount,
	}
	if entry.Claim != nil {
		if entry.Claim.WorkerID != "" {
			metadata["workerId"] = entry.Claim.WorkerID
		}
		if entry.Claim.PID != 0 {
			metadata["pid"] = entry.Claim.PID
		}
		if entry.Claim.Hostname != "" {
			metadata["hostname"] = entry.Claim.Hostname
		}
	}

	if err := appendFactoryRunTimelineEvent(store, entry.RunID, now, factoryTimelineEvent{
		EventType: factory.EventTypeCommandOutputSummary,
		Summary:   "Factory run claimed",
		Metadata:  metadata,
	}); err != nil {
		if restoreErr := store.SaveRun(&previous); restoreErr != nil {
			return errors.Join(err, fmt.Errorf("restore claimed factory run %q: %w", entry.RunID, restoreErr))
		}
		return err
	}
	return nil
}

func validateQueuedFactoryRun(record factory.RunRecord) error {
	if record.Status != factory.RunStatusPending {
		return fmt.Errorf("factory run %q is %q, want %q", record.RunID, record.Status, factory.RunStatusPending)
	}
	if currentStep := strings.TrimSpace(record.CurrentStep); currentStep != factory.QueueStatusQueued {
		return fmt.Errorf("factory run %q is at step %q, want %q", record.RunID, record.CurrentStep, factory.QueueStatusQueued)
	}
	return nil
}

func validateClaimableFactoryRun(record factory.RunRecord, entry factory.QueueEntry) error {
	if record.Status != factory.RunStatusPending {
		return fmt.Errorf("factory run %q is %q, want %q", record.RunID, record.Status, factory.RunStatusPending)
	}
	currentStep := strings.TrimSpace(record.CurrentStep)
	if currentStep == "" || currentStep == factory.RunStatusPending {
		return nil
	}
	if currentStep == factory.QueueStatusQueued {
		return nil
	}
	if currentStep == factory.QueueStatusClaimed && entry.AttemptCount > 1 {
		return nil
	}
	return fmt.Errorf("factory run %q is at step %q, want %q", record.RunID, record.CurrentStep, factory.QueueStatusQueued)
}

func validateClaimedFactoryRun(record factory.RunRecord) error {
	if record.Status != factory.RunStatusPending {
		return fmt.Errorf("factory run %q is %q, want %q", record.RunID, record.Status, factory.RunStatusPending)
	}
	if currentStep := strings.TrimSpace(record.CurrentStep); currentStep != factory.QueueStatusClaimed {
		return fmt.Errorf("factory run %q is at step %q, want %q", record.RunID, record.CurrentStep, factory.QueueStatusClaimed)
	}
	return nil
}

func renderFactoryQueueAddResult(out io.Writer, entry factory.QueueEntry, jsonMode bool) error {
	resp := FactoryQueueAddResponse{
		ContractVersion: FactoryQueueAddContractVersion,
		Entry:           entry,
		Summary:         factoryQueueAddSummary(entry),
	}
	if jsonMode {
		data, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal factory queue add: %w", err)
		}
		fmt.Fprintln(out, string(data))
		return nil
	}

	fmt.Fprintln(out, resp.Summary)
	return nil
}

func renderFactoryQueueListResult(out io.Writer, entries []factory.QueueEntry, jsonMode bool) error {
	if entries == nil {
		entries = []factory.QueueEntry{}
	}

	resp := FactoryQueueListResponse{
		ContractVersion: FactoryQueueListContractVersion,
		Entries:         entries,
		Summary:         factoryQueueListSummary(entries),
	}
	if jsonMode {
		data, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal factory queue list: %w", err)
		}
		fmt.Fprintln(out, string(data))
		return nil
	}

	fmt.Fprintln(out, resp.Summary)
	for _, entry := range entries {
		fmt.Fprintf(out, "%s\t%s\t%s\t%s\n", entry.QueueID, entry.RunID, entry.ExecutorMode, entry.Status)
	}
	return nil
}

func renderFactoryQueueWorkResult(out io.Writer, entry *factory.QueueEntry, jsonMode bool) error {
	resp := FactoryQueueWorkResponse{
		ContractVersion: FactoryQueueWorkContractVersion,
		Claimed:         entry != nil,
		Entry:           entry,
		Summary:         factoryQueueWorkSummary(entry),
	}
	if jsonMode {
		data, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal factory queue work: %w", err)
		}
		fmt.Fprintln(out, string(data))
		return nil
	}

	fmt.Fprintln(out, resp.Summary)
	return nil
}

func factoryQueueAddSummary(entry factory.QueueEntry) string {
	return fmt.Sprintf("queued run %s", entry.RunID)
}

func factoryQueueListSummary(entries []factory.QueueEntry) string {
	count := len(entries)
	if count == 1 {
		return "1 queue entry"
	}
	return fmt.Sprintf("%d queue entries", count)
}

func factoryQueueWorkSummary(entry *factory.QueueEntry) string {
	if entry == nil {
		return "no queued factory work"
	}
	switch entry.Status {
	case factory.QueueStatusSucceeded:
		return fmt.Sprintf("completed queue entry %s", entry.QueueID)
	case factory.QueueStatusFailed:
		return fmt.Sprintf("failed queue entry %s", entry.QueueID)
	}
	return fmt.Sprintf("claimed queue entry %s", entry.QueueID)
}
