package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
	"github.com/spf13/cobra"
)

// Cloud submit flags.
var (
	cloudSubmitRepoFlag        string
	cloudSubmitBaseFlag        string
	cloudSubmitEngineFlag      string
	cloudSubmitAuthProfileFlag string
	cloudSubmitScopeFlag       string
	cloudSubmitJSONFlag        bool
)

// Cloud status flags.
var (
	cloudStatusJSONFlag bool
)

// Cloud logs flags.
var (
	cloudLogsFollowFlag bool
)

// Cloud cancel flags.
var (
	cloudCancelJSONFlag bool
)

var cloudCmd = &cobra.Command{
	Use:   "cloud",
	Short: "Cloud orchestration commands",
	Long: `Manage cloud orchestration runs in Daytona sandboxes.

Commands:
  submit      Submit a new cloud run
  status      Check run status
  logs        View run logs
  cancel      Cancel a running run
  run         Package and submit local .hal state
  pull        Pull final state from a completed run
  auth        Manage auth profiles`,
}

var cloudSubmitCmd = &cobra.Command{
	Use:   "submit",
	Short: "Submit a new cloud run",
	Long: `Submit a new run to cloud orchestration.

Required flags:
  --repo           Repository (owner/repo)
  --base           Base branch name
  --engine         Engine to use (e.g., claude, codex, pi)
  --auth-profile   Auth profile ID
  --scope          Scope reference (e.g., PRD ID)

Output includes run_id, status, engine, auth_profile, and submitted_at.
Use --json for machine-readable output with error codes on failures.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCloudSubmit(
			cloudSubmitRepoFlag,
			cloudSubmitBaseFlag,
			cloudSubmitEngineFlag,
			cloudSubmitAuthProfileFlag,
			cloudSubmitScopeFlag,
			cloudSubmitJSONFlag,
			cloudSubmitStoreFactory,
			cloudSubmitConfigFactory,
			os.Stdout,
		)
	},
}

var cloudStatusCmd = &cobra.Command{
	Use:   "status <run-id>",
	Short: "Check run status",
	Long: `Check the status and health of a cloud run.

Human-readable output includes run_id, status, attempt_count, max_attempts,
current_attempt, last_heartbeat_age, and deadline_at.
Use --json for machine-readable output.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCloudStatus(
			args[0],
			cloudStatusJSONFlag,
			cloudStatusStoreFactory,
			os.Stdout,
		)
	},
}

var cloudLogsCmd = &cobra.Command{
	Use:   "logs <run-id>",
	Short: "View run logs",
	Long: `View historical and live run logs.

Events are displayed ordered by ascending timestamp.
Use --follow to stream new events until interrupted.

Output never includes unredacted secret tokens.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCloudLogs(
			args[0],
			cloudLogsFollowFlag,
			cloudLogsStoreFactory,
			os.Stdout,
			cmd.Context(),
		)
	},
}

var cloudCancelCmd = &cobra.Command{
	Use:   "cancel <run-id>",
	Short: "Cancel a running run",
	Long: `Request cancellation of a cloud run.

Sets the cancel intent on the run. Workers will observe the intent on the
next heartbeat interval and terminate the active attempt.

Output includes run_id, cancel_requested, status, and canceled_at.
Use --json for machine-readable output.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCloudCancel(
			args[0],
			cloudCancelJSONFlag,
			cloudCancelStoreFactory,
			os.Stdout,
		)
	},
}

func init() {
	cloudSubmitCmd.Flags().StringVar(&cloudSubmitRepoFlag, "repo", "", "Repository (owner/repo)")
	cloudSubmitCmd.Flags().StringVar(&cloudSubmitBaseFlag, "base", "", "Base branch name")
	cloudSubmitCmd.Flags().StringVar(&cloudSubmitEngineFlag, "engine", "", "Engine to use")
	cloudSubmitCmd.Flags().StringVar(&cloudSubmitAuthProfileFlag, "auth-profile", "", "Auth profile ID")
	cloudSubmitCmd.Flags().StringVar(&cloudSubmitScopeFlag, "scope", "", "Scope reference")
	cloudSubmitCmd.Flags().BoolVar(&cloudSubmitJSONFlag, "json", false, "Output in JSON format")

	cloudStatusCmd.Flags().BoolVar(&cloudStatusJSONFlag, "json", false, "Output in JSON format")

	cloudLogsCmd.Flags().BoolVar(&cloudLogsFollowFlag, "follow", false, "Stream new events until interrupted")

	cloudCancelCmd.Flags().BoolVar(&cloudCancelJSONFlag, "json", false, "Output in JSON format")

	cloudCmd.AddCommand(cloudSubmitCmd)
	cloudCmd.AddCommand(cloudStatusCmd)
	cloudCmd.AddCommand(cloudLogsCmd)
	cloudCmd.AddCommand(cloudCancelCmd)
	rootCmd.AddCommand(cloudCmd)
}

// cloudSubmitStoreFactory and cloudSubmitConfigFactory are package-level
// variables that tests can override to inject mock stores and configs.
var (
	cloudSubmitStoreFactory  func() (cloud.Store, error)
	cloudSubmitConfigFactory func() cloud.SubmitConfig
)

// cloudStatusStoreFactory is a package-level variable that tests can override.
var cloudStatusStoreFactory func() (cloud.Store, error)

// cloudLogsStoreFactory is a package-level variable that tests can override.
var cloudLogsStoreFactory func() (cloud.Store, error)

// cloudCancelStoreFactory is a package-level variable that tests can override.
var cloudCancelStoreFactory func() (cloud.Store, error)

// cloudSubmitResponse is the JSON output for a successful submit.
type cloudSubmitResponse struct {
	RunID       string `json:"run_id"`
	Status      string `json:"status"`
	Engine      string `json:"engine"`
	AuthProfile string `json:"auth_profile"`
	SubmittedAt string `json:"submitted_at"`
}

// cloudSubmitErrorResponse is the JSON output for a failed submit.
type cloudSubmitErrorResponse struct {
	Error     string `json:"error"`
	ErrorCode string `json:"error_code"`
}

// runCloudSubmit is the testable logic for the cloud submit command.
func runCloudSubmit(
	repo, base, engine, authProfile, scope string,
	jsonOutput bool,
	storeFactory func() (cloud.Store, error),
	configFactory func() cloud.SubmitConfig,
	out io.Writer,
) error {
	// Resolve store and config via factories.
	if storeFactory == nil {
		return writeSubmitError(out, jsonOutput, "store not configured", "configuration_error")
	}

	store, err := storeFactory()
	if err != nil {
		return writeSubmitError(out, jsonOutput, fmt.Sprintf("failed to connect to store: %v", err), "configuration_error")
	}

	config := cloud.SubmitConfig{}
	if configFactory != nil {
		config = configFactory()
	}
	svc := cloud.NewSubmitService(store, config)

	req := &cloud.SubmitRequest{
		Repo:          repo,
		BaseBranch:    base,
		Engine:        engine,
		AuthProfileID: authProfile,
		ScopeRef:      scope,
	}

	ctx := context.Background()
	run, err := svc.Submit(ctx, req)
	if err != nil {
		code := classifySubmitError(err)
		if jsonOutput {
			return writeJSON(out, cloudSubmitErrorResponse{
				Error:     err.Error(),
				ErrorCode: code,
			})
		}
		return fmt.Errorf("submit failed: %w", err)
	}

	if jsonOutput {
		return writeJSON(out, cloudSubmitResponse{
			RunID:       run.ID,
			Status:      string(run.Status),
			Engine:      run.Engine,
			AuthProfile: run.AuthProfileID,
			SubmittedAt: run.CreatedAt.Format(time.RFC3339),
		})
	}

	fmt.Fprintf(out, "Run submitted successfully.\n")
	fmt.Fprintf(out, "  run_id:       %s\n", run.ID)
	fmt.Fprintf(out, "  status:       %s\n", run.Status)
	fmt.Fprintf(out, "  engine:       %s\n", run.Engine)
	fmt.Fprintf(out, "  auth_profile: %s\n", run.AuthProfileID)
	fmt.Fprintf(out, "  submitted_at: %s\n", run.CreatedAt.Format(time.RFC3339))
	return nil
}

// classifySubmitError maps service errors to machine-readable error codes.
func classifySubmitError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()

	// Domain error sentinels (wrapped by SubmitService).
	if cloud.IsNotFound(err) {
		return "not_found"
	}
	if cloud.IsBundleHashMismatch(err) {
		return "bundle_hash_mismatch"
	}

	// SubmitService wraps validation errors with descriptive messages.
	switch {
	case strings.Contains(msg, "must not be empty"):
		return "validation_error"
	case strings.Contains(msg, "validation failed"):
		return "validation_error"
	case strings.Contains(msg, "not linked"):
		return "auth_profile_not_linked"
	case strings.Contains(msg, "not found"):
		return "not_found"
	case strings.Contains(msg, "not compatible"):
		return "engine_provider_mismatch"
	case strings.Contains(msg, "not allowed by policy"):
		return "policy_blocked"
	case strings.Contains(msg, "failed to enqueue"):
		return "store_error"
	default:
		return "unknown_error"
	}
}

// writeSubmitError handles writing an error in the appropriate format.
func writeSubmitError(out io.Writer, jsonOutput bool, msg, code string) error {
	if jsonOutput {
		return writeJSON(out, cloudSubmitErrorResponse{
			Error:     msg,
			ErrorCode: code,
		})
	}
	return fmt.Errorf("%s", msg)
}

// writeJSON marshals v to JSON and writes it to out.
func writeJSON(out io.Writer, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	_, err = fmt.Fprintf(out, "%s\n", data)
	return err
}

// writeCloudError handles writing an error in the appropriate format for cloud commands.
func writeCloudError(out io.Writer, jsonOutput bool, msg, code string) error {
	if jsonOutput {
		return writeJSON(out, cloudErrorResponse{
			Error:     msg,
			ErrorCode: code,
		})
	}
	return fmt.Errorf("%s", msg)
}

// cloudErrorResponse is the JSON output for a cloud command error.
type cloudErrorResponse struct {
	Error     string `json:"error"`
	ErrorCode string `json:"error_code"`
}

// cloudStatusResponse is the JSON output for a successful status query.
type cloudStatusResponse struct {
	RunID                   string  `json:"run_id"`
	Status                  string  `json:"status"`
	AttemptCount            int     `json:"attempt_count"`
	MaxAttempts             int     `json:"max_attempts"`
	CurrentAttempt          *int    `json:"current_attempt"`
	LastHeartbeatAgeSeconds *int64  `json:"last_heartbeat_age_seconds"`
	DeadlineAt              *string `json:"deadline_at"`
	Engine                  string  `json:"engine"`
	AuthProfileID           string  `json:"auth_profile_id"`
}

// runCloudStatus is the testable logic for the cloud status command.
func runCloudStatus(
	runID string,
	jsonOutput bool,
	storeFactory func() (cloud.Store, error),
	out io.Writer,
) error {
	if storeFactory == nil {
		return writeCloudError(out, jsonOutput, "store not configured", "configuration_error")
	}

	store, err := storeFactory()
	if err != nil {
		return writeCloudError(out, jsonOutput, fmt.Sprintf("failed to connect to store: %v", err), "configuration_error")
	}

	ctx := context.Background()
	run, err := store.GetRun(ctx, runID)
	if err != nil {
		if cloud.IsNotFound(err) {
			if jsonOutput {
				_ = writeJSON(out, cloudErrorResponse{
					Error:     fmt.Sprintf("run %q not found", runID),
					ErrorCode: "not_found",
				})
				return fmt.Errorf("run %q not found", runID)
			}
			return fmt.Errorf("run %q not found", runID)
		}
		return writeCloudError(out, jsonOutput, fmt.Sprintf("failed to get run: %v", err), "store_error")
	}

	// Try to get active attempt for heartbeat info.
	var currentAttempt *int
	var lastHeartbeatAge *time.Duration
	attempt, err := store.GetActiveAttemptByRun(ctx, runID)
	if err == nil {
		ca := attempt.AttemptNumber
		currentAttempt = &ca
		age := time.Since(attempt.HeartbeatAt)
		lastHeartbeatAge = &age
	}

	if jsonOutput {
		resp := cloudStatusResponse{
			RunID:        run.ID,
			Status:       string(run.Status),
			AttemptCount: run.AttemptCount,
			MaxAttempts:  run.MaxAttempts,
			Engine:       run.Engine,
			AuthProfileID: run.AuthProfileID,
		}
		if currentAttempt != nil {
			resp.CurrentAttempt = currentAttempt
		}
		if lastHeartbeatAge != nil {
			secs := int64(lastHeartbeatAge.Seconds())
			resp.LastHeartbeatAgeSeconds = &secs
		}
		if run.DeadlineAt != nil {
			d := run.DeadlineAt.Format(time.RFC3339)
			resp.DeadlineAt = &d
		}
		return writeJSON(out, resp)
	}

	// Human-readable output.
	fmt.Fprintf(out, "Run status:\n")
	fmt.Fprintf(out, "  run_id:          %s\n", run.ID)
	fmt.Fprintf(out, "  status:          %s\n", run.Status)
	fmt.Fprintf(out, "  attempt_count:   %d\n", run.AttemptCount)
	fmt.Fprintf(out, "  max_attempts:    %d\n", run.MaxAttempts)
	if currentAttempt != nil {
		fmt.Fprintf(out, "  current_attempt: %d\n", *currentAttempt)
	} else {
		fmt.Fprintf(out, "  current_attempt: none\n")
	}
	if lastHeartbeatAge != nil {
		fmt.Fprintf(out, "  last_heartbeat:  %s ago\n", formatDuration(*lastHeartbeatAge))
	} else {
		fmt.Fprintf(out, "  last_heartbeat:  n/a\n")
	}
	if run.DeadlineAt != nil {
		fmt.Fprintf(out, "  deadline_at:     %s\n", run.DeadlineAt.Format(time.RFC3339))
	} else {
		fmt.Fprintf(out, "  deadline_at:     none\n")
	}
	return nil
}

// formatDuration formats a duration in a human-friendly way.
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}

// cloudLogsFollowPollInterval is the polling interval for --follow mode.
// Package-level variable so tests can override it.
var cloudLogsFollowPollInterval = 2 * time.Second

// runCloudLogs is the testable logic for the cloud logs command.
func runCloudLogs(
	runID string,
	follow bool,
	storeFactory func() (cloud.Store, error),
	out io.Writer,
	ctx context.Context,
) error {
	if storeFactory == nil {
		return writeCloudError(out, false, "store not configured", "configuration_error")
	}

	store, err := storeFactory()
	if err != nil {
		return writeCloudError(out, false, fmt.Sprintf("failed to connect to store: %v", err), "configuration_error")
	}

	// Verify the run exists.
	run, err := store.GetRun(ctx, runID)
	if err != nil {
		if cloud.IsNotFound(err) {
			return fmt.Errorf("run %q not found", runID)
		}
		return fmt.Errorf("failed to get run: %w", err)
	}

	// Fetch and print initial events.
	events, err := store.ListEvents(ctx, runID)
	if err != nil {
		return fmt.Errorf("failed to list events: %w", err)
	}

	seen := make(map[string]bool)
	for _, e := range events {
		formatEvent(out, e)
		seen[e.ID] = true
	}

	if !follow {
		return nil
	}

	// Follow mode: poll for new events until the run reaches a terminal state
	// or context is canceled.
	for {
		if run.Status.IsTerminal() {
			return nil
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(cloudLogsFollowPollInterval):
		}

		// Re-fetch the run status to detect terminal state.
		run, err = store.GetRun(ctx, runID)
		if err != nil {
			return fmt.Errorf("failed to get run: %w", err)
		}

		events, err = store.ListEvents(ctx, runID)
		if err != nil {
			return fmt.Errorf("failed to list events: %w", err)
		}

		for _, e := range events {
			if seen[e.ID] {
				continue
			}
			formatEvent(out, e)
			seen[e.ID] = true
		}
	}
}

// formatEvent writes a single event line to the writer.
func formatEvent(out io.Writer, e *cloud.Event) {
	ts := e.CreatedAt.Format(time.RFC3339)
	if e.PayloadJSON != nil && *e.PayloadJSON != "" {
		fmt.Fprintf(out, "%s  %-24s  %s\n", ts, e.EventType, *e.PayloadJSON)
	} else {
		fmt.Fprintf(out, "%s  %-24s\n", ts, e.EventType)
	}
}

// cloudCancelResponse is the JSON output for a successful cancel request.
type cloudCancelResponse struct {
	RunID           string  `json:"run_id"`
	CancelRequested bool    `json:"cancel_requested"`
	Status          string  `json:"status"`
	CanceledAt      *string `json:"canceled_at"`
}

// runCloudCancel is the testable logic for the cloud cancel command.
func runCloudCancel(
	runID string,
	jsonOutput bool,
	storeFactory func() (cloud.Store, error),
	out io.Writer,
) error {
	if storeFactory == nil {
		return writeCloudError(out, jsonOutput, "store not configured", "configuration_error")
	}

	store, err := storeFactory()
	if err != nil {
		return writeCloudError(out, jsonOutput, fmt.Sprintf("failed to connect to store: %v", err), "configuration_error")
	}

	ctx := context.Background()

	// Set cancel intent.
	svc := cloud.NewCancellationService(store, cloud.CancellationConfig{})
	if err := svc.RequestCancel(ctx, runID); err != nil {
		if cloud.IsNotFound(err) {
			if jsonOutput {
				_ = writeJSON(out, cloudErrorResponse{
					Error:     fmt.Sprintf("run %q not found", runID),
					ErrorCode: "not_found",
				})
				return fmt.Errorf("run %q not found", runID)
			}
			return fmt.Errorf("run %q not found", runID)
		}
		return writeCloudError(out, jsonOutput, fmt.Sprintf("failed to cancel run: %v", err), "store_error")
	}

	// Re-fetch the run to get current state after cancel intent was set.
	run, err := store.GetRun(ctx, runID)
	if err != nil {
		return writeCloudError(out, jsonOutput, fmt.Sprintf("failed to get run: %v", err), "store_error")
	}

	// Determine canceled_at: use UpdatedAt when the run has reached canceled status.
	var canceledAt *string
	if run.Status == cloud.RunStatusCanceled {
		ts := run.UpdatedAt.Format(time.RFC3339)
		canceledAt = &ts
	}

	if jsonOutput {
		return writeJSON(out, cloudCancelResponse{
			RunID:           run.ID,
			CancelRequested: run.CancelRequested,
			Status:          string(run.Status),
			CanceledAt:      canceledAt,
		})
	}

	fmt.Fprintf(out, "Cancel requested.\n")
	fmt.Fprintf(out, "  run_id:           %s\n", run.ID)
	fmt.Fprintf(out, "  cancel_requested: %v\n", run.CancelRequested)
	fmt.Fprintf(out, "  status:           %s\n", run.Status)
	if canceledAt != nil {
		fmt.Fprintf(out, "  canceled_at:      %s\n", *canceledAt)
	} else {
		fmt.Fprintf(out, "  canceled_at:      pending\n")
	}
	return nil
}
