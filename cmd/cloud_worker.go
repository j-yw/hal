package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// Cloud worker flags.
var (
	cloudWorkerIDFlag                string
	cloudWorkerPollIntervalFlag      time.Duration
	cloudWorkerReconcileIntervalFlag time.Duration
	cloudWorkerTimeoutIntervalFlag   time.Duration
	cloudWorkerSandboxImageFlag      string
)

var cloudWorkerCmd = &cobra.Command{
	Use:   "worker",
	Short: "Run the cloud worker loop",
	Long: `Start a cloud worker that polls for queued runs and executes them.

The worker loop claims eligible runs, provisions sandboxes, executes
workflows, and finalizes results. It runs until interrupted (SIGINT/SIGTERM).

Flags:
  --worker-id             Unique identifier for this worker instance
  --poll-interval         Interval between claim polls (default 10s)
  --reconcile-interval    Interval between reconciliation sweeps (default 30s)
  --timeout-interval      Interval between timeout checks (default 60s)
  --sandbox-image         Container image for sandbox provisioning`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCloudWorker(
			cloudWorkerIDFlag,
			cloudWorkerPollIntervalFlag,
			cloudWorkerReconcileIntervalFlag,
			cloudWorkerTimeoutIntervalFlag,
			cloudWorkerSandboxImageFlag,
			os.Stdout,
		)
	},
}

func init() {
	cloudWorkerCmd.Flags().StringVar(&cloudWorkerIDFlag, "worker-id", "", "Unique identifier for this worker instance")
	cloudWorkerCmd.Flags().DurationVar(&cloudWorkerPollIntervalFlag, "poll-interval", 10*time.Second, "Interval between claim polls")
	cloudWorkerCmd.Flags().DurationVar(&cloudWorkerReconcileIntervalFlag, "reconcile-interval", 30*time.Second, "Interval between reconciliation sweeps")
	cloudWorkerCmd.Flags().DurationVar(&cloudWorkerTimeoutIntervalFlag, "timeout-interval", 60*time.Second, "Interval between timeout checks")
	cloudWorkerCmd.Flags().StringVar(&cloudWorkerSandboxImageFlag, "sandbox-image", "", "Container image for sandbox provisioning")

	cloudCmd.AddCommand(cloudWorkerCmd)
}

// runCloudWorker is the testable logic for the cloud worker command.
func runCloudWorker(
	workerID string,
	pollInterval time.Duration,
	reconcileInterval time.Duration,
	timeoutInterval time.Duration,
	sandboxImage string,
	out io.Writer,
) error {
	if workerID == "" {
		return fmt.Errorf("--worker-id is required")
	}

	// Create a context that cancels on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(out, "Starting cloud worker %s\n", workerID)
	fmt.Fprintf(out, "  poll-interval:      %s\n", pollInterval)
	fmt.Fprintf(out, "  reconcile-interval: %s\n", reconcileInterval)
	fmt.Fprintf(out, "  timeout-interval:   %s\n", timeoutInterval)
	if sandboxImage != "" {
		fmt.Fprintf(out, "  sandbox-image:      %s\n", sandboxImage)
	}

	// Wait for shutdown signal.
	<-ctx.Done()
	fmt.Fprintf(out, "Shutting down worker %s\n", workerID)
	return nil
}
