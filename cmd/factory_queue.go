package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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
	defaultStore func() (factory.Store, error)
	now          func() time.Time
	claim        *factory.QueueClaim
	loadPolicy   func(string) (*factory.FactoryPolicy, error)
	runPipeline  func(context.Context, factoryRunPipelineRequest) error
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
	defaultStore: factory.DefaultStore,
	now:          time.Now,
	loadPolicy:   factory.LoadPolicyConfig,
	runPipeline:  runFactoryRunPipeline,
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

	entry, err := store.EnqueueQueueEntry(req.RunID, executorMode, factory.QueueOperationOptions{
		Now:        deps.now,
		NewQueueID: deps.newQueueID,
	})
	if err != nil {
		return fmt.Errorf("enqueue factory run %q: %w", strings.TrimSpace(req.RunID), err)
	}
	if err := recordFactoryRunQueued(store, entry, deps.now()); err != nil {
		return err
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
			finalEntry, failErr := failClaimedFactoryQueueEntry(store, *entry, err, deps.now)
			if failErr != nil {
				return failErr
			}
			if renderErr := renderFactoryQueueWorkResult(out, &finalEntry, req.JSON); renderErr != nil {
				return errors.Join(err, renderErr)
			}
			return err
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
	if _, err := factory.ValidateExecutorMode(entry.ExecutorMode); err != nil {
		return failClaimedFactoryQueueEntry(store, entry, err, deps.now)
	}

	record, err := store.LoadRun(entry.RunID)
	if err != nil {
		return failClaimedFactoryQueueEntry(store, entry, fmt.Errorf("load claimed factory run %q: %w", entry.RunID, err), deps.now)
	}
	record.ExecutorMode = entry.ExecutorMode

	runDir := factoryQueueRunDir(*record)
	policy, err := loadFactoryRunPolicy(runDir, factoryRunDeps{
		loadPolicy: deps.loadPolicy,
	})
	if err != nil {
		return failClaimedFactoryQueueEntry(store, entry, fmt.Errorf("load factory policy: %w", err), deps.now)
	}

	_, execErr := executeFactoryRun(ctx, runDir, factoryRunRequestFromQueueRecord(*record), io.Discard, store, *record, factoryRunDeps{
		now:         deps.now,
		runPipeline: deps.runPipeline,
	}, policy)
	if execErr != nil {
		return failClaimedFactoryQueueEntry(store, entry, execErr, deps.now)
	}

	completedEntry, err := store.MarkQueueEntrySucceeded(entry.QueueID, factory.QueueOperationOptions{
		Now: deps.now,
	})
	if err != nil {
		return entry, err
	}
	return completedEntry, nil
}

func failClaimedFactoryQueueEntry(store factory.Store, entry factory.QueueEntry, cause error, now func() time.Time) (factory.QueueEntry, error) {
	if cause == nil {
		cause = fmt.Errorf("factory queue work failed")
	}
	failedEntry, markErr := store.MarkQueueEntryFailed(entry.QueueID, cause.Error(), factory.QueueOperationOptions{
		Now: now,
	})
	if markErr != nil {
		return entry, errors.Join(cause, markErr)
	}
	return failedEntry, cause
}

func factoryRunRequestFromQueueRecord(record factory.RunRecord) factoryRunRequest {
	req := factoryRunRequest{
		BaseBranch: strings.TrimSpace(record.BaseBranch),
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

func factoryQueueRunDir(record factory.RunRecord) string {
	if dir := strings.TrimSpace(record.RepoPath); dir != "" {
		return dir
	}
	return "."
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
	if deps.loadPolicy == nil {
		deps.loadPolicy = defaultFactoryQueueWorkDeps.loadPolicy
	}
	if deps.runPipeline == nil {
		deps.runPipeline = defaultFactoryQueueWorkDeps.runPipeline
	}
	return deps
}

func recordFactoryRunQueued(store factory.Store, entry factory.QueueEntry, now time.Time) error {
	record, err := store.LoadRun(entry.RunID)
	if err != nil {
		return fmt.Errorf("load queued factory run %q: %w", entry.RunID, err)
	}

	record.CurrentStep = factory.QueueStatusQueued
	record.UpdatedAt = now.UTC()
	if err := store.SaveRun(record); err != nil {
		return fmt.Errorf("record queued factory run %q: %w", entry.RunID, err)
	}

	return appendFactoryRunTimelineEvent(store, entry.RunID, now, factoryTimelineEvent{
		EventType: factory.EventTypeCommandOutputSummary,
		Summary:   "Factory run queued",
		Metadata: map[string]any{
			"queueId":      entry.QueueID,
			"executorMode": entry.ExecutorMode,
			"status":       factory.QueueStatusQueued,
		},
	})
}

func recordFactoryRunClaimed(store factory.Store, entry factory.QueueEntry, now time.Time) error {
	record, err := store.LoadRun(entry.RunID)
	if err != nil {
		return fmt.Errorf("load claimed factory run %q: %w", entry.RunID, err)
	}

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

	return appendFactoryRunTimelineEvent(store, entry.RunID, now, factoryTimelineEvent{
		EventType: factory.EventTypeCommandOutputSummary,
		Summary:   "Factory run claimed",
		Metadata:  metadata,
	})
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
