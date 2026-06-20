package cmd

import (
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

type factoryQueueAddRequest struct {
	RunID        string
	ExecutorMode string
	JSON         bool
}

var defaultFactoryQueueAddDeps = factoryQueueAddDeps{
	defaultStore: factory.DefaultStore,
	now:          time.Now,
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
	return exitWithCode(cmd, ExitCodeExpectedNonZero, errors.New("hal factory queue list is not implemented yet"))
}

func runFactoryQueueWork(cmd *cobra.Command, _ []string) error {
	return exitWithCode(cmd, ExitCodeExpectedNonZero, errors.New("hal factory queue work is not implemented yet"))
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
	if _, err := store.LoadRun(req.RunID); err != nil {
		return fmt.Errorf("load factory run %q: %w", strings.TrimSpace(req.RunID), err)
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

func normalizeFactoryQueueAddDeps(deps factoryQueueAddDeps) factoryQueueAddDeps {
	if deps.defaultStore == nil {
		deps.defaultStore = defaultFactoryQueueAddDeps.defaultStore
	}
	if deps.now == nil {
		deps.now = defaultFactoryQueueAddDeps.now
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

func factoryQueueAddSummary(entry factory.QueueEntry) string {
	return fmt.Sprintf("queued run %s", entry.RunID)
}
