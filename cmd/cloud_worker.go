package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/jywlabs/hal/internal/cloud"
	"github.com/jywlabs/hal/internal/cloud/deploy"
	"github.com/jywlabs/hal/internal/cloud/runner"
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

// defaultWorkerSandboxImage is the fallback image used when --sandbox-image is
// not provided. It must never be empty — ProvisionConfig.Image requires a
// non-empty value so the runner can create a sandbox.
const defaultWorkerSandboxImage = "ubuntu:22.04"

// cloudWorkerStoreFactory is a package-level variable that tests can override.
var cloudWorkerStoreFactory func() (cloud.Store, error)

// cloudWorkerRunnerFactory is a package-level variable that tests can override.
var cloudWorkerRunnerFactory func(cfg deploy.Config) (runner.Runner, error)

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

	if cloudWorkerStoreFactory == nil {
		cloudWorkerStoreFactory = deploy.DefaultStoreFactory
	}
	if cloudWorkerRunnerFactory == nil {
		cloudWorkerRunnerFactory = defaultCloudWorkerRunnerFactory
	}

	cloudCmd.AddCommand(cloudWorkerCmd)
}

// defaultCloudWorkerRunnerFactory constructs a Daytona-backed runner from deploy config.
// The returned *runner.SDKClient satisfies runner.Runner, runner.SessionExec,
// and runner.GitOps interfaces simultaneously.
func defaultCloudWorkerRunnerFactory(cfg deploy.Config) (runner.Runner, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate deploy config: %w", err)
	}
	client, err := runner.NewSDKClient(runner.SDKClientConfig{
		APIKey: cfg.DaytonaAPIKey,
		APIURL: cfg.DaytonaAPIURL,
		Target: cfg.DaytonaTarget,
	})
	if err != nil {
		return nil, fmt.Errorf("create runner client: %w", err)
	}
	return client, nil
}

// resolveWorkerSandboxImage returns the sandbox image to use for provisioning.
// If the provided image (from --sandbox-image flag) is non-empty, it is used
// as-is. Otherwise, defaultWorkerSandboxImage is returned. The result is
// always non-empty.
func resolveWorkerSandboxImage(flagImage string) string {
	if flagImage != "" {
		return flagImage
	}
	return defaultWorkerSandboxImage
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

	// Load .env before deploy config resolution.
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(out, "Warning: failed to load .env file: %v\n", err)
	}

	// Resolve sandbox image — always non-empty.
	image := resolveWorkerSandboxImage(sandboxImage)

	// Create a context that cancels on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(out, "Starting cloud worker %s\n", workerID)
	fmt.Fprintf(out, "  poll-interval:      %s\n", pollInterval)
	fmt.Fprintf(out, "  reconcile-interval: %s\n", reconcileInterval)
	fmt.Fprintf(out, "  timeout-interval:   %s\n", timeoutInterval)
	fmt.Fprintf(out, "  sandbox-image:      %s\n", image)

	// Construct infrastructure from factories.
	store, err := cloudWorkerStoreFactory()
	if err != nil {
		return fmt.Errorf("creating store: %w", err)
	}

	cfg := deploy.LoadConfig(os.Getenv)
	rnr, err := cloudWorkerRunnerFactory(cfg)
	if err != nil {
		return fmt.Errorf("creating runner: %w", err)
	}

	// Build pipeline services.
	claim := cloud.NewClaimService(store, cloud.ClaimConfig{})
	provision := cloud.NewProvisionService(store, rnr, cloud.ProvisionConfig{Image: image})
	bootstrap := cloud.NewBootstrapService(store, rnr, cloud.BootstrapConfig{})
	authMat := cloud.NewAuthMaterializationService(store, rnr, cloud.AuthMaterializationConfig{})
	preflight := cloud.NewPreflightService(store, rnr, cloud.PreflightConfig{})
	checkpoint := cloud.NewCheckpointService(store, nil, cloud.CheckpointConfig{})
	execution := cloud.NewExecutionService(store, rnr, cloud.ExecutionConfig{})
	snapshot := cloud.NewSnapshotService(store, cloud.SnapshotServiceConfig{})
	cancelSvc := cloud.NewCancellationService(store, cloud.CancellationConfig{})
	heartbeat := cloud.NewHeartbeatService(store, cloud.HeartbeatConfig{})
	reconciler := cloud.NewReconcilerService(store, cloud.ReconcilerConfig{})
	timeout := cloud.NewTimeoutService(store, cloud.TimeoutConfig{})

	pipeline, err := cloud.NewWorkerPipeline(cloud.WorkerPipelineConfig{
		Store:               store,
		Runner:              rnr,
		WorkerID:            workerID,
		Claim:               claim,
		Provision:           provision,
		Bootstrap:           bootstrap,
		AuthMaterialization: authMat,
		Preflight:           preflight,
		Checkpoint:          checkpoint,
		Execution:           execution,
		Snapshot:            snapshot,
		Cancel:              cancelSvc,
		Heartbeat:           heartbeat,
		Reconciler:          reconciler,
		Timeout:             timeout,
	})
	if err != nil {
		return fmt.Errorf("creating worker pipeline: %w", err)
	}

	// Run the worker loop until context is canceled (SIGINT/SIGTERM).
	pipeline.RunLoop(ctx, cloud.RunLoopConfig{
		PollInterval:      pollInterval,
		ReconcileInterval: reconcileInterval,
		TimeoutInterval:   timeoutInterval,
	})

	fmt.Fprintf(out, "Shutting down worker %s\n", workerID)
	return nil
}
