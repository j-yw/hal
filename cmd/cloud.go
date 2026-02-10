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

func init() {
	cloudSubmitCmd.Flags().StringVar(&cloudSubmitRepoFlag, "repo", "", "Repository (owner/repo)")
	cloudSubmitCmd.Flags().StringVar(&cloudSubmitBaseFlag, "base", "", "Base branch name")
	cloudSubmitCmd.Flags().StringVar(&cloudSubmitEngineFlag, "engine", "", "Engine to use")
	cloudSubmitCmd.Flags().StringVar(&cloudSubmitAuthProfileFlag, "auth-profile", "", "Auth profile ID")
	cloudSubmitCmd.Flags().StringVar(&cloudSubmitScopeFlag, "scope", "", "Scope reference")
	cloudSubmitCmd.Flags().BoolVar(&cloudSubmitJSONFlag, "json", false, "Output in JSON format")

	cloudCmd.AddCommand(cloudSubmitCmd)
	rootCmd.AddCommand(cloudCmd)
}

// cloudSubmitStoreFactory and cloudSubmitConfigFactory are package-level
// variables that tests can override to inject mock stores and configs.
var (
	cloudSubmitStoreFactory  func() (cloud.Store, error)
	cloudSubmitConfigFactory func() cloud.SubmitConfig
)

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
