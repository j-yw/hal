package cmd

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
	"github.com/jywlabs/hal/internal/cloud/deploy"
	"github.com/spf13/cobra"
)

// Cloud status flags.
var (
	cloudStatusJSONFlag bool
)

// Cloud logs flags.
var (
	cloudLogsFollowFlag bool
	cloudLogsJSONFlag   bool
)

// Cloud cancel flags.
var (
	cloudCancelJSONFlag bool
)

// Cloud pull flags.
var (
	cloudPullForceFlag     bool
	cloudPullJSONFlag      bool
	cloudPullArtifactsFlag string
)

var cloudCmd = &cobra.Command{
	Use:   "cloud",
	Short: "Cloud orchestration commands",
	Long: `Manage cloud orchestration workflows.

Commands:
  setup       Configure cloud defaults
  doctor      Diagnose setup/auth/connectivity
  list        List recent cloud executions
  status      Check execution status
  logs        View execution logs
  cancel      Cancel a running execution
  pull        Pull artifacts from a completed execution
  auth        Manage auth profiles`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
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
			cloudLogsJSONFlag,
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

var cloudPullCmd = &cobra.Command{
	Use:   "pull <run-id>",
	Short: "Pull final state from a completed run",
	Long: `Download the latest final snapshot from a cloud run and restore allowlisted files under .hal/.

Use --artifacts to select which artifact group to pull:
  state    - continuation state files (prd.json, progress.txt, etc.)
  reports  - output reports (.hal/reports/**)
  all      - both state and reports (default)

Refuses to overwrite local files that have changed unless --force is provided.
Prints the restored snapshot version and sha256.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCloudPull(
			args[0],
			cloudPullForceFlag,
			cloudPullJSONFlag,
			cloudPullArtifactsFlag,
			cloudPullStoreFactory,
			".",
			os.Stdout,
		)
	},
}

func init() {
	cloudStatusCmd.Flags().BoolVar(&cloudStatusJSONFlag, "json", false, "Output in JSON format")

	cloudLogsCmd.Flags().BoolVar(&cloudLogsFollowFlag, "follow", false, "Stream new events until interrupted")
	cloudLogsCmd.Flags().BoolVar(&cloudLogsJSONFlag, "json", false, "Output in JSON format")

	cloudCancelCmd.Flags().BoolVar(&cloudCancelJSONFlag, "json", false, "Output in JSON format")

	cloudPullCmd.Flags().BoolVar(&cloudPullForceFlag, "force", false, "Overwrite local files even if changed")
	cloudPullCmd.Flags().BoolVar(&cloudPullJSONFlag, "json", false, "Output in JSON format")
	cloudPullCmd.Flags().StringVar(&cloudPullArtifactsFlag, "artifacts", "all", "Artifact group to pull: state, reports, or all")

	cloudCmd.AddCommand(cloudStatusCmd)
	cloudCmd.AddCommand(cloudLogsCmd)
	cloudCmd.AddCommand(cloudCancelCmd)
	cloudCmd.AddCommand(cloudPullCmd)
	rootCmd.AddCommand(cloudCmd)
}

// cloudStatusStoreFactory is a package-level variable that tests can override.
var cloudStatusStoreFactory func() (cloud.Store, error)

// cloudLogsStoreFactory is a package-level variable that tests can override.
var cloudLogsStoreFactory func() (cloud.Store, error)

// cloudCancelStoreFactory is a package-level variable that tests can override.
var cloudCancelStoreFactory func() (cloud.Store, error)

// cloudPullStoreFactory is a package-level variable that tests can override.
var cloudPullStoreFactory func() (cloud.Store, error)

func init() {
	if cloudStatusStoreFactory == nil {
		cloudStatusStoreFactory = deploy.DefaultStoreFactory
	}
	if cloudLogsStoreFactory == nil {
		cloudLogsStoreFactory = deploy.DefaultStoreFactory
	}
	if cloudCancelStoreFactory == nil {
		cloudCancelStoreFactory = deploy.DefaultStoreFactory
	}
	if cloudPullStoreFactory == nil {
		cloudPullStoreFactory = deploy.DefaultStoreFactory
	}
}

func defaultCloudSubmitConfig() cloud.SubmitConfig {
	return cloud.SubmitConfig{
		IDFunc: defaultCloudRunID,
	}
}

func defaultCloudRunID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("run-%d", time.Now().UTC().UnixNano())
	}
	return "run-" + hex.EncodeToString(raw[:])
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
	WorkflowKind            string  `json:"workflow_kind"`
	Status                  string  `json:"status"`
	AttemptCount            int     `json:"attempt_count"`
	MaxAttempts             int     `json:"max_attempts"`
	CurrentAttempt          *int    `json:"current_attempt"`
	LastHeartbeatAgeSeconds *int64  `json:"last_heartbeat_age_seconds"`
	DeadlineAt              *string `json:"deadline_at"`
	Engine                  string  `json:"engine"`
	AuthProfileID           string  `json:"auth_profile_id"`
	CreatedAt               string  `json:"created_at"`
	UpdatedAt               string  `json:"updated_at"`
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
					ErrorCode: "run_not_found",
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
			RunID:         run.ID,
			WorkflowKind:  string(run.WorkflowKind),
			Status:        string(run.Status),
			AttemptCount:  run.AttemptCount,
			MaxAttempts:   run.MaxAttempts,
			Engine:        run.Engine,
			AuthProfileID: run.AuthProfileID,
			CreatedAt:     run.CreatedAt.Format(time.RFC3339),
			UpdatedAt:     run.UpdatedAt.Format(time.RFC3339),
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
	fmt.Fprintf(out, "  workflow_kind:   %s\n", run.WorkflowKind)
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
	fmt.Fprintf(out, "  created_at:      %s\n", run.CreatedAt.Format(time.RFC3339))
	fmt.Fprintf(out, "  updated_at:      %s\n", run.UpdatedAt.Format(time.RFC3339))
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

// cloudLogsResponse is the JSON output for a successful logs query.
type cloudLogsResponse struct {
	RunID  string               `json:"run_id"`
	Status string               `json:"status"`
	Events []cloudLogsEventJSON `json:"events"`
}

// cloudLogsEventJSON is a single event in the JSON logs response.
type cloudLogsEventJSON struct {
	ID          string  `json:"id"`
	EventType   string  `json:"event_type"`
	PayloadJSON *string `json:"payload_json,omitempty"`
	Redacted    bool    `json:"redacted"`
	CreatedAt   string  `json:"created_at"`
}

// runCloudLogs is the testable logic for the cloud logs command.
func runCloudLogs(
	runID string,
	follow bool,
	jsonOutput bool,
	storeFactory func() (cloud.Store, error),
	out io.Writer,
	ctx context.Context,
) error {
	if storeFactory == nil {
		return writeCloudError(out, jsonOutput, "store not configured", "configuration_error")
	}

	store, err := storeFactory()
	if err != nil {
		return writeCloudError(out, jsonOutput, fmt.Sprintf("failed to connect to store: %v", err), "configuration_error")
	}

	// Verify the run exists.
	run, err := store.GetRun(ctx, runID)
	if err != nil {
		if cloud.IsNotFound(err) {
			if jsonOutput {
				_ = writeJSON(out, cloudErrorResponse{
					Error:     fmt.Sprintf("run %q not found", runID),
					ErrorCode: "run_not_found",
				})
			}
			return fmt.Errorf("run %q not found", runID)
		}
		return writeCloudError(out, jsonOutput, fmt.Sprintf("failed to get run: %v", err), "store_error")
	}

	// Fetch and print initial events.
	events, err := store.ListEvents(ctx, runID)
	if err != nil {
		return writeCloudError(out, jsonOutput, fmt.Sprintf("failed to list events: %v", err), "store_error")
	}

	seen := make(map[string]bool)
	var collected []cloudLogsEventJSON
	for _, e := range events {
		if !jsonOutput {
			formatEvent(out, e)
		}
		if jsonOutput {
			collected = append(collected, eventToJSON(e))
		}
		seen[e.ID] = true
	}

	if !follow {
		if jsonOutput {
			return writeJSON(out, cloudLogsResponse{
				RunID:  run.ID,
				Status: string(run.Status),
				Events: ensureEventSlice(collected),
			})
		}
		return nil
	}

	// Follow mode: poll for new events until the run reaches a terminal state
	// or context is canceled.
	for {
		if run.Status.IsTerminal() {
			if jsonOutput {
				return writeJSON(out, cloudLogsResponse{
					RunID:  run.ID,
					Status: string(run.Status),
					Events: ensureEventSlice(collected),
				})
			}
			return nil
		}

		select {
		case <-ctx.Done():
			if jsonOutput {
				return writeJSON(out, cloudLogsResponse{
					RunID:  run.ID,
					Status: string(run.Status),
					Events: ensureEventSlice(collected),
				})
			}
			return nil
		case <-time.After(cloudLogsFollowPollInterval):
		}

		// Re-fetch the run status to detect terminal state.
		run, err = store.GetRun(ctx, runID)
		if err != nil {
			return writeCloudError(out, jsonOutput, fmt.Sprintf("failed to get run: %v", err), "store_error")
		}

		events, err = store.ListEvents(ctx, runID)
		if err != nil {
			return writeCloudError(out, jsonOutput, fmt.Sprintf("failed to list events: %v", err), "store_error")
		}

		for _, e := range events {
			if seen[e.ID] {
				continue
			}
			if !jsonOutput {
				formatEvent(out, e)
			}
			if jsonOutput {
				collected = append(collected, eventToJSON(e))
			}
			seen[e.ID] = true
		}
	}
}

// eventToJSON converts a cloud Event to a JSON-serializable struct.
func eventToJSON(e *cloud.Event) cloudLogsEventJSON {
	return cloudLogsEventJSON{
		ID:          e.ID,
		EventType:   e.EventType,
		PayloadJSON: e.PayloadJSON,
		Redacted:    e.Redacted,
		CreatedAt:   e.CreatedAt.Format(time.RFC3339),
	}
}

// ensureEventSlice returns a non-nil slice so JSON marshals as [] not null.
func ensureEventSlice(events []cloudLogsEventJSON) []cloudLogsEventJSON {
	if events == nil {
		return make([]cloudLogsEventJSON, 0)
	}
	return events
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
	TerminalStatus  string  `json:"terminal_status,omitempty"`
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

	// Pre-check: if the run is already in a terminal state, return success
	// with already_terminal status and the terminal status value.
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

	if run.Status.IsTerminal() {
		ts := run.UpdatedAt.Format(time.RFC3339)
		if jsonOutput {
			return writeJSON(out, cloudCancelResponse{
				RunID:           run.ID,
				CancelRequested: run.CancelRequested,
				Status:          "already_terminal",
				TerminalStatus:  string(run.Status),
				CanceledAt:      &ts,
			})
		}
		fmt.Fprintf(out, "Run is already terminal.\n")
		fmt.Fprintf(out, "  run_id:           %s\n", run.ID)
		fmt.Fprintf(out, "  status:           already_terminal\n")
		fmt.Fprintf(out, "  terminal_status:  %s\n", run.Status)
		fmt.Fprintf(out, "  canceled_at:      %s\n", ts)
		return nil
	}

	// Set cancel intent on non-terminal run.
	svc := cloud.NewCancellationService(store, cloud.CancellationConfig{})
	if err := svc.RequestCancel(ctx, runID); err != nil {
		return writeCloudError(out, jsonOutput, fmt.Sprintf("failed to cancel run: %v", err), "store_error")
	}

	// Re-fetch the run to get current state after cancel intent was set.
	run, err = store.GetRun(ctx, runID)
	if err != nil {
		return writeCloudError(out, jsonOutput, fmt.Sprintf("failed to get run: %v", err), "store_error")
	}

	if jsonOutput {
		return writeJSON(out, cloudCancelResponse{
			RunID:           run.ID,
			CancelRequested: run.CancelRequested,
			Status:          string(run.Status),
		})
	}

	fmt.Fprintf(out, "Cancel requested.\n")
	fmt.Fprintf(out, "  run_id:           %s\n", run.ID)
	fmt.Fprintf(out, "  cancel_requested: %v\n", run.CancelRequested)
	fmt.Fprintf(out, "  status:           %s\n", run.Status)
	fmt.Fprintf(out, "  canceled_at:      pending\n")
	return nil
}

// collectBundleFiles walks the .hal directory and collects allowlisted files.
// Returns manifest records and a map of path→content for compression.
func collectBundleFiles(baseDir string) ([]cloud.BundleManifestRecord, map[string][]byte, error) {
	halDir := filepath.Join(baseDir, ".hal")
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return nil, nil, fmt.Errorf(".hal directory not found")
	}

	var records []cloud.BundleManifestRecord
	fileContents := make(map[string][]byte)

	err := filepath.Walk(halDir, func(absPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		// Compute relative path from baseDir (e.g., ".hal/prd.json").
		relPath, err := filepath.Rel(baseDir, absPath)
		if err != nil {
			return err
		}
		relPath = filepath.ToSlash(relPath)

		if !cloud.IsBundlePathAllowed(relPath) {
			return nil
		}

		content, err := os.ReadFile(absPath)
		if err != nil {
			return fmt.Errorf("reading %s: %w", relPath, err)
		}

		record := cloud.NewBundleManifestRecord(relPath, content)
		records = append(records, record)
		fileContents[record.Path] = content
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	return records, fileContents, nil
}

// compressBundleFiles compresses collected file contents into a gzip archive.
func compressBundleFiles(records []cloud.BundleManifestRecord, fileContents map[string][]byte) ([]byte, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)

	for _, r := range records {
		content, ok := fileContents[r.Path]
		if !ok {
			continue
		}
		// Write path length + path + content for simple framing.
		header := fmt.Sprintf("%s\x00%d\x00", r.Path, len(content))
		if _, err := gw.Write([]byte(header)); err != nil {
			return nil, err
		}
		if _, err := gw.Write(content); err != nil {
			return nil, err
		}
	}

	if err := gw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// cloudPullResponse is the JSON output for a successful pull command.
type cloudPullResponse struct {
	RunID           string   `json:"run_id"`
	SnapshotVersion int      `json:"snapshot_version"`
	SHA256          string   `json:"sha256"`
	Artifacts       string   `json:"artifacts"`
	FilesRestored   []string `json:"files_restored"`
}

// bundleFileRecord is a decompressed file from a snapshot bundle.
type bundleFileRecord struct {
	Path    string
	Content []byte
}

// runCloudPull is the testable logic for the cloud pull command.
func runCloudPull(
	runID string,
	force, jsonOutput bool,
	artifactsFlag string,
	storeFactory func() (cloud.Store, error),
	baseDir string,
	out io.Writer,
) error {
	if storeFactory == nil {
		return writeCloudError(out, jsonOutput, "store not configured", "configuration_error")
	}

	// Validate --artifacts flag.
	artifactGroup := cloud.ArtifactGroup(artifactsFlag)
	if !artifactGroup.IsValid() {
		msg := fmt.Sprintf("invalid --artifacts value %q; allowed values: state, reports, all", artifactsFlag)
		return writeCloudError(out, jsonOutput, msg, "invalid_flag")
	}

	// Get artifact patterns for the selected group.
	patterns, err := cloud.ArtifactGroupPatterns(artifactGroup)
	if err != nil {
		return writeCloudError(out, jsonOutput, fmt.Sprintf("failed to resolve artifact patterns: %v", err), "invalid_flag")
	}

	store, err := storeFactory()
	if err != nil {
		return writeCloudError(out, jsonOutput, fmt.Sprintf("failed to connect to store: %v", err), "configuration_error")
	}

	ctx := context.Background()

	// Verify the run exists.
	if _, err := store.GetRun(ctx, runID); err != nil {
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

	// Get the latest snapshot.
	snapshot, err := store.GetLatestSnapshot(ctx, runID)
	if err != nil {
		if cloud.IsNotFound(err) {
			return writeCloudError(out, jsonOutput, fmt.Sprintf("no snapshot found for run %q", runID), "not_found")
		}
		return writeCloudError(out, jsonOutput, fmt.Sprintf("failed to get snapshot: %v", err), "store_error")
	}

	// Decompress the bundle content.
	files, err := decompressBundleFiles(snapshot.ContentBlob)
	if err != nil {
		return writeCloudError(out, jsonOutput, fmt.Sprintf("failed to decompress snapshot: %v", err), "bundle_error")
	}

	// Filter files by artifact patterns. Unlike uploads (which use BundleAllowlist),
	// pull uses artifact group patterns to determine which files are pullable.
	// Reports are excluded from uploads but are valid pull artifacts.
	isAllowed := func(path string) bool {
		return cloud.MatchesArtifactPatterns(path, patterns)
	}

	// Check for local file changes unless --force.
	if !force {
		var changed []string
		for _, f := range files {
			if !isAllowed(f.Path) {
				continue
			}
			targetPath := filepath.Join(baseDir, f.Path)
			existing, err := os.ReadFile(targetPath)
			if err != nil {
				continue // file doesn't exist locally — safe to write
			}
			if !bytes.Equal(existing, f.Content) {
				changed = append(changed, f.Path)
			}
		}
		if len(changed) > 0 {
			msg := fmt.Sprintf("local files changed, use --force to overwrite: %s", strings.Join(changed, ", "))
			return writeCloudError(out, jsonOutput, msg, "local_changes")
		}
	}

	// Write files to .hal/.
	var restored []string
	for _, f := range files {
		if !isAllowed(f.Path) {
			continue
		}
		targetPath := filepath.Join(baseDir, f.Path)
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return writeCloudError(out, jsonOutput, fmt.Sprintf("failed to create directory for %s: %v", f.Path, err), "restore_error")
		}
		if err := os.WriteFile(targetPath, f.Content, 0644); err != nil {
			return writeCloudError(out, jsonOutput, fmt.Sprintf("failed to write %s: %v", f.Path, err), "restore_error")
		}
		restored = append(restored, f.Path)
	}

	if jsonOutput {
		resp := cloudPullResponse{
			RunID:           runID,
			SnapshotVersion: snapshot.Version,
			SHA256:          snapshot.SHA256,
			Artifacts:       string(artifactGroup),
			FilesRestored:   restored,
		}
		if resp.FilesRestored == nil {
			resp.FilesRestored = make([]string, 0)
		}
		return writeJSON(out, resp)
	}

	fmt.Fprintf(out, "Snapshot restored successfully.\n")
	fmt.Fprintf(out, "  snapshot_version: %d\n", snapshot.Version)
	fmt.Fprintf(out, "  sha256:           %s\n", snapshot.SHA256)
	fmt.Fprintf(out, "  files restored:   %d\n", len(restored))
	for _, p := range restored {
		fmt.Fprintf(out, "    %s\n", p)
	}
	return nil
}

// decompressBundleFiles decompresses a gzip bundle into file records.
// The format matches compressBundleFiles: path\x00size\x00content for each file.
func decompressBundleFiles(data []byte) ([]bundleFileRecord, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip open: %w", err)
	}
	defer gr.Close()

	decompressed, err := io.ReadAll(gr)
	if err != nil {
		return nil, fmt.Errorf("gzip read: %w", err)
	}

	var files []bundleFileRecord
	pos := 0
	for pos < len(decompressed) {
		// Read path (terminated by \x00).
		nullIdx := bytes.IndexByte(decompressed[pos:], 0x00)
		if nullIdx < 0 {
			return nil, fmt.Errorf("malformed bundle: missing path null terminator at offset %d", pos)
		}
		filePath := string(decompressed[pos : pos+nullIdx])
		pos += nullIdx + 1

		// Read size (terminated by \x00).
		nullIdx = bytes.IndexByte(decompressed[pos:], 0x00)
		if nullIdx < 0 {
			return nil, fmt.Errorf("malformed bundle: missing size null terminator at offset %d", pos)
		}
		sizeStr := string(decompressed[pos : pos+nullIdx])
		pos += nullIdx + 1

		var size int
		if _, err := fmt.Sscanf(sizeStr, "%d", &size); err != nil {
			return nil, fmt.Errorf("malformed bundle: invalid size %q: %w", sizeStr, err)
		}

		if pos+size > len(decompressed) {
			return nil, fmt.Errorf("malformed bundle: content overflows at offset %d (need %d bytes, have %d)", pos, size, len(decompressed)-pos)
		}

		content := make([]byte, size)
		copy(content, decompressed[pos:pos+size])
		pos += size

		files = append(files, bundleFileRecord{
			Path:    filePath,
			Content: content,
		})
	}

	return files, nil
}
