package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
	cloudconfig "github.com/jywlabs/hal/internal/cloud/config"
	"github.com/jywlabs/hal/internal/cloud/deploy"
	"github.com/jywlabs/hal/internal/template"
)

// runCloudFlags holds the shared cloud flags registered on the run command.
var runCloudFlags *CloudFlags

// runCloudStoreFactory is a package-level variable that tests can override.
var runCloudStoreFactory func() (cloud.Store, error)

// runCloudConfigFactory is a package-level variable that tests can override.
var runCloudConfigFactory func() cloud.SubmitConfig

// runCloudPollInterval is the polling interval for wait mode.
// Package-level variable so tests can override it.
var runCloudPollInterval = 2 * time.Second

func init() {
	runCloudFlags = RegisterCloudFlags(runCmd)

	if runCloudStoreFactory == nil {
		runCloudStoreFactory = deploy.DefaultStoreFactory
	}
	if runCloudConfigFactory == nil {
		runCloudConfigFactory = defaultCloudSubmitConfig
	}
}

// runCloudRunResponse is the JSON output for a successful hal run --cloud.
type runCloudRunResponse struct {
	RunID        string `json:"runId"`
	WorkflowKind string `json:"workflowKind"`
	Status       string `json:"status"`
}

// runCloudRunErrorResponse is the JSON output for a failed hal run --cloud.
type runCloudRunErrorResponse struct {
	Error     string `json:"error"`
	ErrorCode string `json:"error_code"`
}

// executeRunCloud handles the hal run --cloud flow. Returns true if --cloud
// was set and the cloud path was taken (caller should return), false if
// the normal local flow should continue.
func executeRunCloud(cmd_unused interface{}, out io.Writer) (bool, error) {
	if runCloudFlags == nil || !runCloudFlags.Cloud {
		return false, nil
	}
	err := runHalRunCloud(
		runCloudFlags,
		template.HalDir,
		".",
		runCloudStoreFactory,
		runCloudConfigFactory,
		out,
	)
	return true, err
}

// runHalRunCloud is the testable logic for hal run --cloud.
func runHalRunCloud(
	flags *CloudFlags,
	halDir string,
	baseDir string,
	storeFactory func() (cloud.Store, error),
	configFactory func() cloud.SubmitConfig,
	out io.Writer,
) error {
	jsonOutput := flags.JSON

	// 1. Validate flag combinations.
	if err := ValidateCloudFlags(flags); err != nil {
		fe := err.(*CloudFlagError)
		return writeRunCloudError(out, jsonOutput, fe.Message, fe.Code)
	}

	// 2. Resolve cloud config.
	resolved, err := cloudconfig.Resolve(cloudconfig.ResolveInput{
		CLIFlags: &cloudconfig.CLIFlags{
			Mode:        flags.CloudMode,
			Endpoint:    flags.CloudEndpoint,
			Repo:        flags.CloudRepo,
			Base:        flags.CloudBase,
			AuthProfile: flags.CloudAuthProfile,
			Scope:       flags.CloudAuthScope,
		},
		ProfileName:  flags.CloudProfile,
		HalDir:       halDir,
		WorkflowKind: "run",
		CloudEnabled: true,
	})
	if err != nil {
		return writeRunCloudError(out, jsonOutput, fmt.Sprintf("config resolution failed: %v", err), "configuration_error")
	}

	// 3. Check .hal directory exists.
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return writeRunCloudError(out, jsonOutput, ".hal/ not found. Run 'hal init' first", "prerequisite_error")
	}

	// 4. Collect and bundle .hal files.
	records, fileContents, err := collectBundleFiles(baseDir)
	if err != nil {
		return writeRunCloudError(out, jsonOutput, fmt.Sprintf("failed to collect bundle files: %v", err), "bundle_error")
	}
	if len(records) == 0 {
		return writeRunCloudError(out, jsonOutput, "no allowlisted files found in .hal/", "bundle_error")
	}

	manifest := cloud.NewBundleManifest(records)
	bundleContent, err := compressBundleFiles(records, fileContents)
	if err != nil {
		return writeRunCloudError(out, jsonOutput, fmt.Sprintf("failed to compress bundle: %v", err), "bundle_error")
	}

	// 5. Submit to cloud store.
	if storeFactory == nil {
		return writeRunCloudError(out, jsonOutput, "store not configured", "configuration_error")
	}
	store, err := storeFactory()
	if err != nil {
		return writeRunCloudError(out, jsonOutput, fmt.Sprintf("failed to connect to store: %v", err), "configuration_error")
	}

	config := cloud.SubmitConfig{}
	if configFactory != nil {
		config = configFactory()
	}
	svc := cloud.NewSubmitService(store, config)

	req := &cloud.SubmitRequest{
		Repo:          resolved.Repo,
		BaseBranch:    resolved.Base,
		WorkflowKind:  cloud.WorkflowKindRun,
		Engine:        resolved.Engine,
		AuthProfileID: resolved.AuthProfile,
		ScopeRef:      resolved.Scope,
	}

	bundle := &cloud.BundlePayload{
		Manifest: manifest,
		Content:  bundleContent,
	}

	ctx := context.Background()
	run, err := svc.SubmitWithBundle(ctx, req, bundle)
	if err != nil {
		code := classifySubmitError(err)
		return writeRunCloudError(out, jsonOutput, fmt.Sprintf("submit failed: %v", err), code)
	}

	// 6. Determine wait behavior: --detach means don't wait, --wait means wait,
	//    otherwise use resolved default.
	shouldWait := resolved.Wait
	if flags.Detach {
		shouldWait = false
	}
	if flags.Wait {
		shouldWait = true
	}

	if !shouldWait {
		// Detach mode: print submission info and return.
		return writeRunCloudSuccess(out, jsonOutput, run)
	}

	// 7. Wait mode: poll until terminal status.
	if !jsonOutput {
		fmt.Fprintf(out, "Run submitted.\n")
		fmt.Fprintf(out, "  run_id: %s\n", cloud.Redact(run.ID))
		fmt.Fprintf(out, "  status: %s\n", cloud.Redact(string(run.Status)))
		fmt.Fprintf(out, "Waiting for completion...\n")
	}

	finalRun, err := pollRunUntilTerminal(ctx, store, run.ID, out, jsonOutput)
	if err != nil {
		return writeRunCloudError(out, jsonOutput, fmt.Sprintf("failed while waiting: %v", err), "store_error")
	}

	return writeRunCloudTerminal(out, jsonOutput, finalRun)
}

// pollRunUntilTerminal polls the store until the run reaches a terminal status.
func pollRunUntilTerminal(ctx context.Context, store cloud.Store, runID string, out io.Writer, jsonOutput bool) (*cloud.Run, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(runCloudPollInterval):
		}

		run, err := store.GetRun(ctx, runID)
		if err != nil {
			return nil, fmt.Errorf("failed to get run: %w", err)
		}

		if run.Status.IsTerminal() {
			return run, nil
		}
	}
}

// writeRunCloudSuccess writes the submission result (used in detach mode).
func writeRunCloudSuccess(out io.Writer, jsonOutput bool, run *cloud.Run) error {
	// Redact secrets from run fields that may contain user-supplied values.
	runID := cloud.Redact(run.ID)
	status := cloud.Redact(string(run.Status))
	workflowKind := cloud.Redact(string(run.WorkflowKind))

	if jsonOutput {
		return writeJSON(out, runCloudRunResponse{
			RunID:        runID,
			WorkflowKind: workflowKind,
			Status:       status,
		})
	}

	fmt.Fprintf(out, "Run submitted.\n")
	fmt.Fprintf(out, "  run_id: %s\n", runID)
	fmt.Fprintf(out, "  status: %s\n", status)
	fmt.Fprintf(out, "\nNext: hal cloud status %s\n", runID)
	return nil
}

// writeRunCloudTerminal writes the final result after a run reaches terminal status.
func writeRunCloudTerminal(out io.Writer, jsonOutput bool, run *cloud.Run) error {
	// Redact secrets from run fields that may contain user-supplied values.
	runID := cloud.Redact(run.ID)
	status := cloud.Redact(string(run.Status))
	workflowKind := cloud.Redact(string(run.WorkflowKind))

	if jsonOutput {
		return writeJSON(out, runCloudRunResponse{
			RunID:        runID,
			WorkflowKind: workflowKind,
			Status:       status,
		})
	}

	fmt.Fprintf(out, "Run complete.\n")
	fmt.Fprintf(out, "  run_id: %s\n", runID)
	fmt.Fprintf(out, "  status: %s\n", status)
	fmt.Fprintf(out, "\nNext: hal cloud logs %s\n", runID)
	return nil
}

// writeRunCloudError writes an error in the appropriate format for hal run --cloud.
// In human mode, writes structured error fields to output for deterministic parsing,
// then returns a Go error to signal non-zero exit.
func writeRunCloudError(out io.Writer, jsonOutput bool, msg, code string) error {
	// Redact secrets from error messages that may contain user-supplied values.
	msg = cloud.Redact(msg)

	if jsonOutput {
		return writeJSON(out, runCloudRunErrorResponse{
			Error:     msg,
			ErrorCode: code,
		})
	}
	fmt.Fprintf(out, "Error: %s\n", msg)
	fmt.Fprintf(out, "  error: %s\n", msg)
	fmt.Fprintf(out, "  error_code: %s\n", code)
	return fmt.Errorf("%s", msg)
}
