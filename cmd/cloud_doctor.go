package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/jywlabs/hal/internal/cloud/config"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

// Cloud doctor flags.
var (
	cloudDoctorProfileFlag string
	cloudDoctorJSONFlag    bool
)

var cloudDoctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Diagnose cloud configuration and connectivity",
	Long: `Validate cloud profile resolution, endpoint reachability, and auth profile configuration.

Performs explicit checks:
  1. Profile/config resolution — loads and validates .hal/cloud.yaml
  2. Endpoint reachability — HTTP HEAD to the configured endpoint
  3. Auth profile validity — verifies auth profile is configured

Blocking failures include category-specific next-step guidance.
Exit code is non-zero for blocking failures, zero when all checks pass.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		halDir := filepath.Join(".", template.HalDir)
		return runCloudDoctor(halDir, cloudDoctorProfileFlag, cloudDoctorJSONFlag, cloudDoctorHTTPClient, os.Stdout)
	},
}

func init() {
	cloudDoctorCmd.Flags().StringVar(&cloudDoctorProfileFlag, "profile", "", "Profile name to diagnose (default: use defaultProfile from cloud.yaml)")
	cloudDoctorCmd.Flags().BoolVar(&cloudDoctorJSONFlag, "json", false, "Output in JSON format")
	cloudCmd.AddCommand(cloudDoctorCmd)
}

// cloudDoctorHTTPClient is injectable for testing endpoint reachability.
var cloudDoctorHTTPClient httpDoer = &http.Client{Timeout: 10 * time.Second}

// httpDoer abstracts http.Client for testing.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// doctorCheckResult represents the result of a single diagnostic check.
type doctorCheckResult struct {
	Name     string `json:"name"`
	Status   string `json:"status"` // "pass", "fail", "warn"
	Message  string `json:"message"`
	NextStep string `json:"next_step,omitempty"`
}

// cloudDoctorResponse is the JSON output for the doctor command.
type cloudDoctorResponse struct {
	Overall string              `json:"overall"` // "pass" or "fail"
	Checks  []doctorCheckResult `json:"checks"`
}

// runCloudDoctor is the testable logic for the cloud doctor command.
func runCloudDoctor(halDir, profileFlag string, jsonOutput bool, client httpDoer, out io.Writer) error {
	var checks []doctorCheckResult
	hasFailure := false

	// Check 1: Profile/config resolution.
	configCheck, resolvedCfg, resolvedProfile := checkProfileResolution(halDir, profileFlag)
	checks = append(checks, configCheck)
	if configCheck.Status == "fail" {
		hasFailure = true
	}

	// Check 2: Endpoint reachability.
	endpointCheck := checkEndpointReachability(resolvedCfg, client)
	checks = append(checks, endpointCheck)
	if endpointCheck.Status == "fail" {
		hasFailure = true
	}

	// Check 3: Auth profile validity.
	authCheck := checkAuthProfileValidity(resolvedCfg, resolvedProfile)
	checks = append(checks, authCheck)
	if authCheck.Status == "fail" {
		hasFailure = true
	}

	overall := "pass"
	if hasFailure {
		overall = "fail"
	}

	if jsonOutput {
		err := writeJSON(out, cloudDoctorResponse{
			Overall: overall,
			Checks:  checks,
		})
		if err != nil {
			return err
		}
		if hasFailure {
			return fmt.Errorf("doctor found blocking failures")
		}
		return nil
	}

	// Human-readable output.
	fmt.Fprintf(out, "Cloud doctor diagnostics:\n\n")
	for _, c := range checks {
		icon := "PASS"
		if c.Status == "fail" {
			icon = "FAIL"
		} else if c.Status == "warn" {
			icon = "WARN"
		}
		fmt.Fprintf(out, "  [%s] %s\n", icon, c.Name)
		fmt.Fprintf(out, "         %s\n", c.Message)
		if c.NextStep != "" {
			fmt.Fprintf(out, "         Next step: %s\n", c.NextStep)
		}
		fmt.Fprintln(out)
	}

	if hasFailure {
		fmt.Fprintf(out, "Result: FAIL — resolve blocking failures above.\n")
		return fmt.Errorf("doctor found blocking failures")
	}

	fmt.Fprintf(out, "Result: PASS — cloud configuration looks good.\n")
	return nil
}

// checkProfileResolution validates .hal/cloud.yaml loading and profile resolution.
// Returns the check result plus the resolved config and profile for downstream checks.
func checkProfileResolution(halDir, profileFlag string) (doctorCheckResult, *config.ResolvedConfig, *config.Profile) {
	configPath := filepath.Join(halDir, template.CloudConfigFile)

	// Try to load the cloud config file.
	cfg, err := config.Load(configPath)
	if err != nil {
		return doctorCheckResult{
			Name:     "profile_resolution",
			Status:   "fail",
			Message:  fmt.Sprintf("Failed to load %s: %v", configPath, err),
			NextStep: "Run hal cloud setup to create or fix cloud configuration.",
		}, nil, nil
	}

	// Resolve the profile.
	profile := cfg.GetProfile(profileFlag)
	profileName := profileFlag
	if profileName == "" {
		profileName = cfg.DefaultProfile
	}
	if profileName == "" {
		profileName = "(none)"
	}

	if profile == nil {
		return doctorCheckResult{
			Name:     "profile_resolution",
			Status:   "fail",
			Message:  fmt.Sprintf("Profile %q not found in %s.", profileName, configPath),
			NextStep: "Run hal cloud setup to configure the profile.",
		}, nil, nil
	}

	// Run resolution to verify full precedence chain works.
	resolved, err := config.Resolve(config.ResolveInput{
		CLIFlags:     nil,
		ProfileName:  profileFlag,
		HalDir:       halDir,
		WorkflowKind: "run",
		CloudEnabled: true,
	})
	if err != nil {
		return doctorCheckResult{
			Name:     "profile_resolution",
			Status:   "fail",
			Message:  fmt.Sprintf("Config resolution failed: %v", err),
			NextStep: "Run hal cloud setup to fix cloud configuration.",
		}, nil, profile
	}

	return doctorCheckResult{
		Name:    "profile_resolution",
		Status:  "pass",
		Message: fmt.Sprintf("Profile %q resolved successfully from %s.", profileName, configPath),
	}, resolved, profile
}

// checkEndpointReachability performs an HTTP HEAD request to the configured endpoint.
func checkEndpointReachability(resolved *config.ResolvedConfig, client httpDoer) doctorCheckResult {
	if resolved == nil {
		return doctorCheckResult{
			Name:     "endpoint_reachability",
			Status:   "fail",
			Message:  "Skipped — config resolution failed.",
			NextStep: "Resolve config issues first, then rerun hal cloud doctor.",
		}
	}

	endpoint := resolved.Endpoint
	if endpoint == "" {
		return doctorCheckResult{
			Name:     "endpoint_reachability",
			Status:   "fail",
			Message:  "No endpoint configured.",
			NextStep: "Set an endpoint via hal cloud setup, --cloud-endpoint flag, or HAL_CLOUD_ENDPOINT env var.",
		}
	}

	req, err := http.NewRequest(http.MethodHead, endpoint, nil)
	if err != nil {
		return doctorCheckResult{
			Name:     "endpoint_reachability",
			Status:   "fail",
			Message:  fmt.Sprintf("Invalid endpoint URL %q: %v", endpoint, err),
			NextStep: "Verify the endpoint URL and rerun hal cloud doctor.",
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return doctorCheckResult{
			Name:     "endpoint_reachability",
			Status:   "fail",
			Message:  fmt.Sprintf("Endpoint %q is not reachable: %v", endpoint, err),
			NextStep: "Verify the endpoint URL and rerun hal cloud doctor.",
		}
	}
	resp.Body.Close()

	if resp.StatusCode >= 500 {
		return doctorCheckResult{
			Name:     "endpoint_reachability",
			Status:   "fail",
			Message:  fmt.Sprintf("Endpoint %q returned server error (HTTP %d).", endpoint, resp.StatusCode),
			NextStep: "Verify the endpoint URL and rerun hal cloud doctor.",
		}
	}

	return doctorCheckResult{
		Name:    "endpoint_reachability",
		Status:  "pass",
		Message: fmt.Sprintf("Endpoint %q is reachable (HTTP %d).", endpoint, resp.StatusCode),
	}
}

// checkAuthProfileValidity verifies that an auth profile is configured.
func checkAuthProfileValidity(resolved *config.ResolvedConfig, profile *config.Profile) doctorCheckResult {
	if resolved == nil {
		return doctorCheckResult{
			Name:     "auth_profile_validity",
			Status:   "fail",
			Message:  "Skipped — config resolution failed.",
			NextStep: "Resolve config issues first, then rerun hal cloud doctor.",
		}
	}

	authProfile := resolved.AuthProfile
	if authProfile == "" {
		return doctorCheckResult{
			Name:     "auth_profile_validity",
			Status:   "fail",
			Message:  "No auth profile configured.",
			NextStep: "Link or import credentials for the active profile: hal cloud auth link --profile <id> --provider <name>.",
		}
	}

	return doctorCheckResult{
		Name:    "auth_profile_validity",
		Status:  "pass",
		Message: fmt.Sprintf("Auth profile %q is configured.", authProfile),
	}
}
