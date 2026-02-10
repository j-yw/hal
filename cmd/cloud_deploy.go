package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jywlabs/hal/internal/cloud/deploy"
	"github.com/spf13/cobra"
)

// Cloud smoke flags.
var (
	cloudSmokeControlPlaneFlag string
	cloudSmokeRunnerFlag       string
	cloudSmokeJSONFlag         bool
)

var cloudSmokeCmd = &cobra.Command{
	Use:   "smoke",
	Short: "Verify control-plane and runner health endpoints",
	Long: `Run smoke checks against the control-plane and runner health endpoints.

Verifies that both services return HTTP 200. Use after deployment to confirm
services are running correctly.

Examples:
  hal cloud smoke --control-plane http://localhost:8080 --runner http://localhost:8090
  hal cloud smoke --json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCloudSmoke(
			cloudSmokeControlPlaneFlag,
			cloudSmokeRunnerFlag,
			cloudSmokeJSONFlag,
			os.Stdout,
		)
	},
}

var cloudEnvCmd = &cobra.Command{
	Use:   "env",
	Short: "Validate deployment environment variables",
	Long: `Validate that all required environment variables are set for the configured
database adapter. Fails fast with a clear message if any required variable is missing.

Default adapter is "turso" when HAL_CLOUD_DB_ADAPTER is not set.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCloudEnv(os.Getenv, os.Stdout)
	},
}

func init() {
	cloudSmokeCmd.Flags().StringVar(&cloudSmokeControlPlaneFlag, "control-plane", "http://localhost:8080", "Control-plane service URL")
	cloudSmokeCmd.Flags().StringVar(&cloudSmokeRunnerFlag, "runner", "http://localhost:8090", "Runner service URL")
	cloudSmokeCmd.Flags().BoolVar(&cloudSmokeJSONFlag, "json", false, "Output in JSON format")

	cloudCmd.AddCommand(cloudSmokeCmd)
	cloudCmd.AddCommand(cloudEnvCmd)
}

// runCloudSmoke is the testable logic for the cloud smoke command.
func runCloudSmoke(
	controlPlaneURL, runnerURL string,
	jsonOutput bool,
	out io.Writer,
) error {
	if controlPlaneURL == "" {
		return writeCloudError(out, jsonOutput, "--control-plane URL is required", "validation_error")
	}
	if runnerURL == "" {
		return writeCloudError(out, jsonOutput, "--runner URL is required", "validation_error")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if !jsonOutput {
		fmt.Fprintf(out, "Running smoke checks...\n")
	}

	report := deploy.RunSmoke(ctx, controlPlaneURL, runnerURL, nil)

	if err := deploy.WriteSmokeReport(out, report, jsonOutput); err != nil {
		return err
	}

	if !report.AllOK {
		return fmt.Errorf("smoke check failed: some services are unhealthy")
	}
	return nil
}

// runCloudEnv is the testable logic for the cloud env command.
func runCloudEnv(getenv func(string) string, out io.Writer) error {
	cfg := deploy.LoadConfig(getenv)
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(out, "Environment validation failed: %v\n", err)
		return err
	}

	fmt.Fprintf(out, "Environment OK.\n")
	fmt.Fprintf(out, "  adapter:        %s\n", cfg.DBAdapter)
	fmt.Fprintf(out, "  runner_url:     %s\n", cfg.RunnerURL)
	if cfg.DBAdapter == deploy.AdapterTurso {
		fmt.Fprintf(out, "  turso_url:      %s\n", cfg.TursoURL)
	} else {
		fmt.Fprintf(out, "  postgres_dsn:   (set)\n")
	}
	return nil
}
