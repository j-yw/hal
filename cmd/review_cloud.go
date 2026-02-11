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

// reviewCloudFlags holds the shared cloud flags registered on the review command.
var reviewCloudFlags *CloudFlags

// reviewCloudStoreFactory is a package-level variable that tests can override.
var reviewCloudStoreFactory func() (cloud.Store, error)

// reviewCloudConfigFactory is a package-level variable that tests can override.
var reviewCloudConfigFactory func() cloud.SubmitConfig

// reviewCloudPollInterval is the polling interval for wait mode.
// Package-level variable so tests can override it.
var reviewCloudPollInterval = 2 * time.Second

func init() {
	reviewCloudFlags = RegisterCloudFlags(reviewCmd)

	if reviewCloudStoreFactory == nil {
		reviewCloudStoreFactory = deploy.DefaultStoreFactory
	}
	if reviewCloudConfigFactory == nil {
		reviewCloudConfigFactory = defaultCloudSubmitConfig
	}
}

// reviewCloudResponse is the JSON output for a successful hal review --cloud.
type reviewCloudResponse struct {
	RunID        string `json:"runId"`
	WorkflowKind string `json:"workflowKind"`
	Status       string `json:"status"`
}

// reviewCloudErrorResponse is the JSON output for a failed hal review --cloud.
type reviewCloudErrorResponse struct {
	Error     string `json:"error"`
	ErrorCode string `json:"error_code"`
}

// executeReviewCloud handles the hal review --cloud flow. Returns true if --cloud
// was set and the cloud path was taken (caller should return), false if
// the normal local flow should continue.
func executeReviewCloud(cmd_unused interface{}, out io.Writer) (bool, error) {
	if reviewCloudFlags == nil || !reviewCloudFlags.Cloud {
		return false, nil
	}
	err := runHalReviewCloud(
		reviewCloudFlags,
		template.HalDir,
		".",
		reviewCloudStoreFactory,
		reviewCloudConfigFactory,
		out,
	)
	return true, err
}

// runHalReviewCloud is the testable logic for hal review --cloud.
func runHalReviewCloud(
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
			return writeJSON(out, reviewCloudErrorResponse{
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
		WorkflowKind: "review",
		CloudEnabled: true,
	})
	if err != nil {
		return writeReviewCloudError(out, jsonOutput, fmt.Sprintf("config resolution failed: %v", err), "configuration_error")
	}

	// 3. Check .hal directory exists.
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return writeReviewCloudError(out, jsonOutput, ".hal/ not found. Run 'hal init' first", "prerequisite_error")
	}

	// 4. Collect and bundle .hal files.
	records, fileContents, err := collectBundleFiles(baseDir)
	if err != nil {
		return writeReviewCloudError(out, jsonOutput, fmt.Sprintf("failed to collect bundle files: %v", err), "bundle_error")
	}
	if len(records) == 0 {
		return writeReviewCloudError(out, jsonOutput, "no allowlisted files found in .hal/", "bundle_error")
	}

	manifest := cloud.NewBundleManifest(records)
	bundleContent, err := compressBundleFiles(records, fileContents)
	if err != nil {
		return writeReviewCloudError(out, jsonOutput, fmt.Sprintf("failed to compress bundle: %v", err), "bundle_error")
	}

	// 5. Submit to cloud store.
	if storeFactory == nil {
		return writeReviewCloudError(out, jsonOutput, "store not configured", "configuration_error")
	}
	store, err := storeFactory()
	if err != nil {
		return writeReviewCloudError(out, jsonOutput, fmt.Sprintf("failed to connect to store: %v", err), "configuration_error")
	}

	config := cloud.SubmitConfig{}
	if configFactory != nil {
		config = configFactory()
	}
	svc := cloud.NewSubmitService(store, config)

	req := &cloud.SubmitRequest{
		Repo:          resolved.Repo,
		BaseBranch:    resolved.Base,
		WorkflowKind:  cloud.WorkflowKindReview,
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
		return writeReviewCloudError(out, jsonOutput, fmt.Sprintf("submit failed: %v", err), code)
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
		return writeReviewCloudSuccess(out, jsonOutput, run)
	}

	// 7. Wait mode: poll until terminal status.
	if !jsonOutput {
		fmt.Fprintf(out, "Review run submitted.\n")
		fmt.Fprintf(out, "  run_id: %s\n", cloud.Redact(run.ID))
		fmt.Fprintf(out, "  status: %s\n", cloud.Redact(string(run.Status)))
		fmt.Fprintf(out, "Waiting for completion...\n")
	}

	finalRun, err := pollReviewRunUntilTerminal(ctx, store, run.ID, out, jsonOutput)
	if err != nil {
		return writeReviewCloudError(out, jsonOutput, fmt.Sprintf("failed while waiting: %v", err), "store_error")
	}

	return writeReviewCloudTerminal(out, jsonOutput, finalRun)
}

// pollReviewRunUntilTerminal polls the store until the run reaches a terminal status.
func pollReviewRunUntilTerminal(ctx context.Context, store cloud.Store, runID string, out io.Writer, jsonOutput bool) (*cloud.Run, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(reviewCloudPollInterval):
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

// writeReviewCloudSuccess writes the submission result (used in detach mode).
func writeReviewCloudSuccess(out io.Writer, jsonOutput bool, run *cloud.Run) error {
	runID := cloud.Redact(run.ID)
	workflowKind := cloud.Redact(string(run.WorkflowKind))
	status := cloud.Redact(string(run.Status))

	if jsonOutput {
		return writeJSON(out, reviewCloudResponse{
			RunID:        runID,
			WorkflowKind: workflowKind,
			Status:       status,
		})
	}

	fmt.Fprintf(out, "Review run submitted.\n")
	fmt.Fprintf(out, "  run_id: %s\n", runID)
	fmt.Fprintf(out, "  status: %s\n", status)
	fmt.Fprintf(out, "\nNext: hal cloud status %s\n", runID)
	return nil
}

// writeReviewCloudTerminal writes the final result after a run reaches terminal status.
func writeReviewCloudTerminal(out io.Writer, jsonOutput bool, run *cloud.Run) error {
	runID := cloud.Redact(run.ID)
	workflowKind := cloud.Redact(string(run.WorkflowKind))
	status := cloud.Redact(string(run.Status))

	if jsonOutput {
		return writeJSON(out, reviewCloudResponse{
			RunID:        runID,
			WorkflowKind: workflowKind,
			Status:       status,
		})
	}

	fmt.Fprintf(out, "Review run complete.\n")
	fmt.Fprintf(out, "  run_id: %s\n", runID)
	fmt.Fprintf(out, "  status: %s\n", status)
	fmt.Fprintf(out, "\nArtifacts available: state, reports\n")
	fmt.Fprintf(out, "Next: hal cloud pull %s\n", runID)
	fmt.Fprintf(out, "       hal cloud logs %s\n", runID)
	return nil
}

// writeReviewCloudError writes an error in the appropriate format for hal review --cloud.
func writeReviewCloudError(out io.Writer, jsonOutput bool, msg, code string) error {
	msg = cloud.Redact(msg)

	if jsonOutput {
		return writeJSON(out, reviewCloudErrorResponse{
			Error:     msg,
			ErrorCode: code,
		})
	}
	return fmt.Errorf("%s", msg)
}
