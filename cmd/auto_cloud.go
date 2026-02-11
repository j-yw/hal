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

// autoCloudFlags holds the shared cloud flags registered on the auto command.
var autoCloudFlags *CloudFlags

// autoCloudStoreFactory is a package-level variable that tests can override.
var autoCloudStoreFactory func() (cloud.Store, error)

// autoCloudConfigFactory is a package-level variable that tests can override.
var autoCloudConfigFactory func() cloud.SubmitConfig

// autoCloudPollInterval is the polling interval for wait mode.
// Package-level variable so tests can override it.
var autoCloudPollInterval = 2 * time.Second

func init() {
	autoCloudFlags = RegisterCloudFlags(autoCmd)

	if autoCloudStoreFactory == nil {
		autoCloudStoreFactory = deploy.DefaultStoreFactory
	}
	if autoCloudConfigFactory == nil {
		autoCloudConfigFactory = defaultCloudSubmitConfig
	}
}

// autoCloudResponse is the JSON output for a successful hal auto --cloud.
type autoCloudResponse struct {
	RunID        string `json:"runId"`
	WorkflowKind string `json:"workflowKind"`
	Status       string `json:"status"`
}

// autoCloudErrorResponse is the JSON output for a failed hal auto --cloud.
type autoCloudErrorResponse struct {
	Error     string `json:"error"`
	ErrorCode string `json:"error_code"`
}

// executeAutoCloud handles the hal auto --cloud flow. Returns true if --cloud
// was set and the cloud path was taken (caller should return), false if
// the normal local flow should continue.
func executeAutoCloud(cmd_unused interface{}, out io.Writer) (bool, error) {
	if autoCloudFlags == nil || !autoCloudFlags.Cloud {
		return false, nil
	}
	err := runHalAutoCloud(
		autoCloudFlags,
		template.HalDir,
		".",
		autoCloudStoreFactory,
		autoCloudConfigFactory,
		out,
	)
	return true, err
}

// runHalAutoCloud is the testable logic for hal auto --cloud.
func runHalAutoCloud(
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
		if jsonOutput {
			fe := err.(*CloudFlagError)
			return writeJSON(out, autoCloudErrorResponse{
				Error:     fe.Message,
				ErrorCode: fe.Code,
			})
		}
		return err
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
		WorkflowKind: "auto",
		CloudEnabled: true,
	})
	if err != nil {
		return writeAutoCloudError(out, jsonOutput, fmt.Sprintf("config resolution failed: %v", err), "configuration_error")
	}

	// 3. Check .hal directory exists.
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return writeAutoCloudError(out, jsonOutput, ".hal/ not found. Run 'hal init' first", "prerequisite_error")
	}

	// 4. Collect and bundle .hal files.
	records, fileContents, err := collectBundleFiles(baseDir)
	if err != nil {
		return writeAutoCloudError(out, jsonOutput, fmt.Sprintf("failed to collect bundle files: %v", err), "bundle_error")
	}
	if len(records) == 0 {
		return writeAutoCloudError(out, jsonOutput, "no allowlisted files found in .hal/", "bundle_error")
	}

	manifest := cloud.NewBundleManifest(records)
	bundleContent, err := compressBundleFiles(records, fileContents)
	if err != nil {
		return writeAutoCloudError(out, jsonOutput, fmt.Sprintf("failed to compress bundle: %v", err), "bundle_error")
	}

	// 5. Submit to cloud store.
	if storeFactory == nil {
		return writeAutoCloudError(out, jsonOutput, "store not configured", "configuration_error")
	}
	store, err := storeFactory()
	if err != nil {
		return writeAutoCloudError(out, jsonOutput, fmt.Sprintf("failed to connect to store: %v", err), "configuration_error")
	}

	config := cloud.SubmitConfig{}
	if configFactory != nil {
		config = configFactory()
	}
	svc := cloud.NewSubmitService(store, config)

	req := &cloud.SubmitRequest{
		Repo:          resolved.Repo,
		BaseBranch:    resolved.Base,
		WorkflowKind:  cloud.WorkflowKindAuto,
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
		return writeAutoCloudError(out, jsonOutput, fmt.Sprintf("submit failed: %v", err), code)
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
		return writeAutoCloudSuccess(out, jsonOutput, run)
	}

	// 7. Wait mode: poll until terminal status.
	if !jsonOutput {
		fmt.Fprintf(out, "Auto run submitted.\n")
		fmt.Fprintf(out, "  run_id: %s\n", run.ID)
		fmt.Fprintf(out, "  status: %s\n", run.Status)
		fmt.Fprintf(out, "Waiting for completion...\n")
	}

	finalRun, err := pollAutoRunUntilTerminal(ctx, store, run.ID, out, jsonOutput)
	if err != nil {
		return writeAutoCloudError(out, jsonOutput, fmt.Sprintf("failed while waiting: %v", err), "store_error")
	}

	return writeAutoCloudTerminal(out, jsonOutput, finalRun)
}

// pollAutoRunUntilTerminal polls the store until the run reaches a terminal status.
func pollAutoRunUntilTerminal(ctx context.Context, store cloud.Store, runID string, out io.Writer, jsonOutput bool) (*cloud.Run, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(autoCloudPollInterval):
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

// writeAutoCloudSuccess writes the submission result (used in detach mode).
func writeAutoCloudSuccess(out io.Writer, jsonOutput bool, run *cloud.Run) error {
	if jsonOutput {
		return writeJSON(out, autoCloudResponse{
			RunID:        run.ID,
			WorkflowKind: string(run.WorkflowKind),
			Status:       string(run.Status),
		})
	}

	fmt.Fprintf(out, "Auto run submitted.\n")
	fmt.Fprintf(out, "  run_id: %s\n", run.ID)
	fmt.Fprintf(out, "  status: %s\n", run.Status)
	fmt.Fprintf(out, "\nNext: hal cloud status %s\n", run.ID)
	return nil
}

// writeAutoCloudTerminal writes the final result after a run reaches terminal status.
func writeAutoCloudTerminal(out io.Writer, jsonOutput bool, run *cloud.Run) error {
	if jsonOutput {
		return writeJSON(out, autoCloudResponse{
			RunID:        run.ID,
			WorkflowKind: string(run.WorkflowKind),
			Status:       string(run.Status),
		})
	}

	fmt.Fprintf(out, "Auto run complete.\n")
	fmt.Fprintf(out, "  run_id: %s\n", run.ID)
	fmt.Fprintf(out, "  status: %s\n", run.Status)
	fmt.Fprintf(out, "\nArtifacts available: state, reports\n")
	fmt.Fprintf(out, "Next: hal cloud pull %s\n", run.ID)
	fmt.Fprintf(out, "       hal cloud logs %s\n", run.ID)
	return nil
}

// writeAutoCloudError writes an error in the appropriate format for hal auto --cloud.
func writeAutoCloudError(out io.Writer, jsonOutput bool, msg, code string) error {
	if jsonOutput {
		return writeJSON(out, autoCloudErrorResponse{
			Error:     msg,
			ErrorCode: code,
		})
	}
	return fmt.Errorf("%s", msg)
}
