package cmd

import (
	"errors"

	"github.com/spf13/cobra"
)

var factoryQueueAddJSONFlag bool
var factoryQueueListJSONFlag bool
var factoryQueueWorkJSONFlag bool

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
	Args:  exactArgsValidation(2),
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

func runFactoryQueueAdd(cmd *cobra.Command, _ []string) error {
	return exitWithCode(cmd, ExitCodeExpectedNonZero, errors.New("hal factory queue add is not implemented yet"))
}

func runFactoryQueueList(cmd *cobra.Command, _ []string) error {
	return exitWithCode(cmd, ExitCodeExpectedNonZero, errors.New("hal factory queue list is not implemented yet"))
}

func runFactoryQueueWork(cmd *cobra.Command, _ []string) error {
	return exitWithCode(cmd, ExitCodeExpectedNonZero, errors.New("hal factory queue work is not implemented yet"))
}
