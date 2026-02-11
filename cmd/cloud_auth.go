package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
	"github.com/jywlabs/hal/internal/cloud/deploy"
	"github.com/spf13/cobra"
)

// Cloud auth link flags.
var (
	cloudAuthLinkProviderFlag string
	cloudAuthLinkProfileFlag  string
	cloudAuthLinkSecretFlag   string
	cloudAuthLinkOwnerFlag    string
	cloudAuthLinkModeFlag     string
	cloudAuthLinkJSONFlag     bool
)

// Cloud auth import flags.
var (
	cloudAuthImportProviderFlag string
	cloudAuthImportProfileFlag  string
	cloudAuthImportSourceFlag   string
	cloudAuthImportOwnerFlag    string
	cloudAuthImportModeFlag     string
	cloudAuthImportJSONFlag     bool
)

// Cloud auth status flags.
var (
	cloudAuthStatusJSONFlag bool
)

// Cloud auth validate flags.
var (
	cloudAuthValidateJSONFlag bool
)

// Cloud auth revoke flags.
var (
	cloudAuthRevokeJSONFlag bool
)

var cloudAuthCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage auth profiles",
	Long: `Manage auth profiles for cloud orchestration.

Commands:
  link        Link an auth profile to a provider
  import      Import local auth artifacts into a profile
  status      Show auth profile readiness and lock status
  validate    Run provider validation checks on a profile
  revoke      Revoke an auth profile`,
}

var cloudAuthLinkCmd = &cobra.Command{
	Use:   "link",
	Short: "Link an auth profile to a provider",
	Long: `Initiate a provider flow and link an auth profile from the operator environment.

Required flags:
  --provider    Provider name (e.g., anthropic, openai)
  --profile     Auth profile ID

Optional flags:
  --secret      Encrypted secret reference
  --owner       Owner ID (defaults to "operator")
  --mode        Auth mode (defaults to "session")

The command stores the encrypted secret reference and emits an audit event.
Use --json for machine-readable output.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCloudAuthLink(
			cloudAuthLinkProviderFlag,
			cloudAuthLinkProfileFlag,
			cloudAuthLinkSecretFlag,
			cloudAuthLinkOwnerFlag,
			cloudAuthLinkModeFlag,
			cloudAuthLinkJSONFlag,
			cloudAuthLinkStoreFactory,
			os.Stdout,
		)
	},
}

var cloudAuthImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import local auth artifacts into a profile",
	Long: `Import local authenticated artifacts when interactive link is unavailable.

Required flags:
  --provider    Provider name (e.g., anthropic, openai)
  --profile     Auth profile ID
  --source      Path to local auth artifacts

Optional flags:
  --owner       Owner ID (defaults to "operator")
  --mode        Auth mode (defaults to "imported")

The command reads local auth artifacts, encrypts them, and stores the
encrypted secret reference. An audit event is recorded with the profile
ID and provider.
Use --json for machine-readable output.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCloudAuthImport(
			cloudAuthImportProviderFlag,
			cloudAuthImportProfileFlag,
			cloudAuthImportSourceFlag,
			cloudAuthImportOwnerFlag,
			cloudAuthImportModeFlag,
			cloudAuthImportJSONFlag,
			cloudAuthImportStoreFactory,
			cloudAuthImportCredentialValidator,
			os.Stdout,
		)
	},
}

var cloudAuthStatusCmd = &cobra.Command{
	Use:   "status <profile>",
	Short: "Show auth profile readiness and lock status",
	Long: `Show provider, profile state, lock owner, lock expiry, and compatibility summary.

Missing profile exits non-zero with error code not_found.
Use --json for machine-readable output.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCloudAuthStatus(
			args[0],
			cloudAuthStatusJSONFlag,
			cloudAuthStatusStoreFactory,
			os.Stdout,
		)
	},
}

var cloudAuthValidateCmd = &cobra.Command{
	Use:   "validate <profile>",
	Short: "Run provider validation checks on a profile",
	Long: `Run provider validation checks on an auth profile.

Success updates last_validated_at and clears last_error_code.
Failure sets last_error_code to auth_invalid or auth_profile_incompatible
and exits non-zero.
Use --json for machine-readable output.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCloudAuthValidate(
			args[0],
			cloudAuthValidateJSONFlag,
			cloudAuthValidateStoreFactory,
			os.Stdout,
		)
	},
}

var cloudAuthRevokeCmd = &cobra.Command{
	Use:   "revoke <profile>",
	Short: "Revoke an auth profile",
	Long: `Revoke an auth profile for compromised or invalid credentials.

Transitions the profile status to revoked and emits an audit event.
Missing profile exits non-zero with error code not_found.
Use --json for machine-readable output.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCloudAuthRevoke(
			args[0],
			cloudAuthRevokeJSONFlag,
			cloudAuthRevokeStoreFactory,
			os.Stdout,
		)
	},
}

func init() {
	cloudAuthLinkCmd.Flags().StringVar(&cloudAuthLinkProviderFlag, "provider", "", "Provider name (e.g., anthropic, openai)")
	cloudAuthLinkCmd.Flags().StringVar(&cloudAuthLinkProfileFlag, "profile", "", "Auth profile ID")
	cloudAuthLinkCmd.Flags().StringVar(&cloudAuthLinkSecretFlag, "secret", "", "Encrypted secret reference")
	cloudAuthLinkCmd.Flags().StringVar(&cloudAuthLinkOwnerFlag, "owner", "", "Owner ID")
	cloudAuthLinkCmd.Flags().StringVar(&cloudAuthLinkModeFlag, "mode", "", "Auth mode")
	cloudAuthLinkCmd.Flags().BoolVar(&cloudAuthLinkJSONFlag, "json", false, "Output in JSON format")

	cloudAuthImportCmd.Flags().StringVar(&cloudAuthImportProviderFlag, "provider", "", "Provider name (e.g., anthropic, openai)")
	cloudAuthImportCmd.Flags().StringVar(&cloudAuthImportProfileFlag, "profile", "", "Auth profile ID")
	cloudAuthImportCmd.Flags().StringVar(&cloudAuthImportSourceFlag, "source", "", "Path to local auth artifacts")
	cloudAuthImportCmd.Flags().StringVar(&cloudAuthImportOwnerFlag, "owner", "", "Owner ID")
	cloudAuthImportCmd.Flags().StringVar(&cloudAuthImportModeFlag, "mode", "", "Auth mode")
	cloudAuthImportCmd.Flags().BoolVar(&cloudAuthImportJSONFlag, "json", false, "Output in JSON format")

	cloudAuthStatusCmd.Flags().BoolVar(&cloudAuthStatusJSONFlag, "json", false, "Output in JSON format")

	cloudAuthValidateCmd.Flags().BoolVar(&cloudAuthValidateJSONFlag, "json", false, "Output in JSON format")

	cloudAuthRevokeCmd.Flags().BoolVar(&cloudAuthRevokeJSONFlag, "json", false, "Output in JSON format")

	cloudAuthCmd.AddCommand(cloudAuthLinkCmd)
	cloudAuthCmd.AddCommand(cloudAuthImportCmd)
	cloudAuthCmd.AddCommand(cloudAuthStatusCmd)
	cloudAuthCmd.AddCommand(cloudAuthValidateCmd)
	cloudAuthCmd.AddCommand(cloudAuthRevokeCmd)
	cloudCmd.AddCommand(cloudAuthCmd)
}

func init() {
	if cloudAuthLinkStoreFactory == nil {
		cloudAuthLinkStoreFactory = deploy.DefaultStoreFactory
	}
	if cloudAuthImportStoreFactory == nil {
		cloudAuthImportStoreFactory = deploy.DefaultStoreFactory
	}
	if cloudAuthStatusStoreFactory == nil {
		cloudAuthStatusStoreFactory = deploy.DefaultStoreFactory
	}
	if cloudAuthValidateStoreFactory == nil {
		cloudAuthValidateStoreFactory = deploy.DefaultStoreFactory
	}
	if cloudAuthRevokeStoreFactory == nil {
		cloudAuthRevokeStoreFactory = deploy.DefaultStoreFactory
	}
}

// cloudAuthLinkStoreFactory is a package-level variable that tests can override.
var cloudAuthLinkStoreFactory func() (cloud.Store, error)

// cloudAuthLinkResponse is the JSON output for a successful auth link.
type cloudAuthLinkResponse struct {
	ProfileID string `json:"profile_id"`
	Provider  string `json:"provider"`
	Status    string `json:"status"`
	LinkedAt  string `json:"linked_at"`
}

// runCloudAuthLink is the testable logic for the cloud auth link command.
func runCloudAuthLink(
	provider, profile, secret, owner, mode string,
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

	svc := cloud.NewAuthLinkService(store, cloud.AuthLinkConfig{})

	req := &cloud.AuthLinkRequest{
		Provider:  provider,
		ProfileID: profile,
		SecretRef: secret,
		OwnerID:   owner,
		Mode:      mode,
	}

	ctx := context.Background()
	result, err := svc.Link(ctx, req)
	if err != nil {
		code := classifyAuthLinkError(err)
		if jsonOutput {
			return writeJSON(out, cloudErrorResponse{
				Error:     err.Error(),
				ErrorCode: code,
			})
		}
		return fmt.Errorf("auth link failed: %w", err)
	}

	if jsonOutput {
		return writeJSON(out, cloudAuthLinkResponse{
			ProfileID: result.ProfileID,
			Provider:  result.Provider,
			Status:    result.Status,
			LinkedAt:  result.LinkedAt.Format(time.RFC3339),
		})
	}

	fmt.Fprintf(out, "Auth profile linked successfully.\n")
	fmt.Fprintf(out, "  profile_id: %s\n", result.ProfileID)
	fmt.Fprintf(out, "  provider:   %s\n", result.Provider)
	fmt.Fprintf(out, "  status:     %s\n", result.Status)
	fmt.Fprintf(out, "  linked_at:  %s\n", result.LinkedAt.Format(time.RFC3339))
	return nil
}

// classifyAuthLinkError maps service errors to machine-readable error codes.
func classifyAuthLinkError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()

	switch {
	case strings.Contains(msg, "must not be empty") || strings.Contains(msg, "validation failed"):
		return "validation_error"
	case strings.Contains(msg, "already exists"):
		return "duplicate_profile"
	case strings.Contains(msg, "failed to create"):
		return "store_error"
	default:
		return "unknown_error"
	}
}

// cloudAuthImportStoreFactory is a package-level variable that tests can override.
var cloudAuthImportStoreFactory func() (cloud.Store, error)

// cloudAuthImportCredentialValidator is a package-level variable for credential validation.
// Tests can override this to inject mock validation behavior.
var cloudAuthImportCredentialValidator func(ctx context.Context, provider, source string) error

// cloudAuthImportResponse is the JSON output for a successful auth import.
type cloudAuthImportResponse struct {
	ProfileID  string `json:"profile_id"`
	Provider   string `json:"provider"`
	Status     string `json:"status"`
	ImportedAt string `json:"imported_at"`
}

// runCloudAuthImport is the testable logic for the cloud auth import command.
func runCloudAuthImport(
	provider, profile, source, owner, mode string,
	jsonOutput bool,
	storeFactory func() (cloud.Store, error),
	credentialValidator func(ctx context.Context, provider, source string) error,
	out io.Writer,
) error {
	if storeFactory == nil {
		return writeCloudError(out, jsonOutput, "store not configured", "configuration_error")
	}

	store, err := storeFactory()
	if err != nil {
		return writeCloudError(out, jsonOutput, fmt.Sprintf("failed to connect to store: %v", err), "configuration_error")
	}

	svc := cloud.NewAuthImportService(store, cloud.AuthImportConfig{
		CredentialValidator: credentialValidator,
	})

	req := &cloud.AuthImportRequest{
		Provider:  provider,
		ProfileID: profile,
		Source:    source,
		OwnerID:   owner,
		Mode:      mode,
	}

	ctx := context.Background()
	result, err := svc.Import(ctx, req)
	if err != nil {
		code := classifyAuthImportError(err)
		if jsonOutput {
			return writeJSON(out, cloudErrorResponse{
				Error:     err.Error(),
				ErrorCode: code,
			})
		}
		return fmt.Errorf("auth import failed: %w", err)
	}

	if jsonOutput {
		return writeJSON(out, cloudAuthImportResponse{
			ProfileID:  result.ProfileID,
			Provider:   result.Provider,
			Status:     result.Status,
			ImportedAt: result.ImportedAt.Format(time.RFC3339),
		})
	}

	fmt.Fprintf(out, "Auth profile imported successfully.\n")
	fmt.Fprintf(out, "  profile_id:  %s\n", result.ProfileID)
	fmt.Fprintf(out, "  provider:    %s\n", result.Provider)
	fmt.Fprintf(out, "  status:      %s\n", result.Status)
	fmt.Fprintf(out, "  imported_at: %s\n", result.ImportedAt.Format(time.RFC3339))
	return nil
}

// classifyAuthImportError maps service errors to machine-readable error codes.
func classifyAuthImportError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()

	switch {
	case strings.Contains(msg, "must not be empty") || strings.Contains(msg, "validation failed"):
		return "validation_error"
	case strings.Contains(msg, "invalid credentials"):
		return "invalid_credentials"
	case strings.Contains(msg, "already exists"):
		return "duplicate_profile"
	case strings.Contains(msg, "failed to create"):
		return "store_error"
	default:
		return "unknown_error"
	}
}

// cloudAuthStatusStoreFactory is a package-level variable that tests can override.
var cloudAuthStatusStoreFactory func() (cloud.Store, error)

// cloudAuthStatusResponse is the JSON output for a successful auth status query.
type cloudAuthStatusResponse struct {
	ProfileID       string  `json:"profileId"`
	Status          string  `json:"status"`
	LastValidatedAt *string `json:"lastValidatedAt,omitempty"`
}

// mapAuthProfileStatus maps internal auth profile statuses to user-facing status strings.
// pending_link → missing, all others pass through.
func mapAuthProfileStatus(s cloud.AuthProfileStatus) string {
	if s == cloud.AuthProfileStatusPendingLink {
		return "missing"
	}
	return string(s)
}

// runCloudAuthStatus is the testable logic for the cloud auth status command.
func runCloudAuthStatus(
	profileID string,
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
	profile, err := store.GetAuthProfile(ctx, profileID)
	if err != nil {
		if cloud.IsNotFound(err) {
			// Missing profile is a reportable state, not an error.
			if jsonOutput {
				return writeJSON(out, cloudAuthStatusResponse{
					ProfileID: profileID,
					Status:    "missing",
				})
			}
			fmt.Fprintf(out, "Auth profile status:\n")
			fmt.Fprintf(out, "  profileId: %s\n", profileID)
			fmt.Fprintf(out, "  status:    missing\n")
			return nil
		}
		return writeCloudError(out, jsonOutput, fmt.Sprintf("failed to get profile: %v", err), "store_error")
	}

	status := mapAuthProfileStatus(profile.Status)

	if jsonOutput {
		resp := cloudAuthStatusResponse{
			ProfileID: profile.ID,
			Status:    status,
		}
		if profile.LastValidatedAt != nil {
			ts := profile.LastValidatedAt.Format(time.RFC3339)
			resp.LastValidatedAt = &ts
		}
		return writeJSON(out, resp)
	}

	// Human-readable output.
	fmt.Fprintf(out, "Auth profile status:\n")
	fmt.Fprintf(out, "  profileId: %s\n", profile.ID)
	fmt.Fprintf(out, "  status:    %s\n", status)
	if profile.LastValidatedAt != nil {
		fmt.Fprintf(out, "  lastValidatedAt: %s\n", profile.LastValidatedAt.Format(time.RFC3339))
	}
	return nil
}

// cloudAuthValidateStoreFactory is a package-level variable that tests can override.
var cloudAuthValidateStoreFactory func() (cloud.Store, error)

// cloudAuthValidateResponse is the JSON output for a successful auth validate.
type cloudAuthValidateResponse struct {
	ProfileID   string `json:"profileId"`
	Status      string `json:"status"`
	ValidatedAt string `json:"validatedAt"`
}

// runCloudAuthValidate is the testable logic for the cloud auth validate command.
func runCloudAuthValidate(
	profileID string,
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

	svc := cloud.NewAuthValidateService(store, cloud.AuthValidateConfig{})

	req := &cloud.AuthValidateRequest{
		ProfileID: profileID,
	}

	ctx := context.Background()
	result, err := svc.Validate(ctx, req)
	if err != nil {
		code := classifyAuthValidateError(err)
		if jsonOutput {
			_ = writeJSON(out, cloudErrorResponse{
				Error:     err.Error(),
				ErrorCode: code,
			})
			return fmt.Errorf("auth validate failed: %w", err)
		}
		return fmt.Errorf("auth validate failed: %w", err)
	}

	if jsonOutput {
		return writeJSON(out, cloudAuthValidateResponse{
			ProfileID:   result.ProfileID,
			Status:      result.Status,
			ValidatedAt: result.ValidatedAt.Format(time.RFC3339),
		})
	}

	fmt.Fprintf(out, "Auth profile validated successfully.\n")
	fmt.Fprintf(out, "  profileId:    %s\n", result.ProfileID)
	fmt.Fprintf(out, "  status:       %s\n", result.Status)
	fmt.Fprintf(out, "  validatedAt:  %s\n", result.ValidatedAt.Format(time.RFC3339))
	return nil
}

// classifyAuthValidateError maps service errors to machine-readable error codes.
func classifyAuthValidateError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()

	switch {
	case strings.Contains(msg, "must not be empty") || strings.Contains(msg, "validation failed"):
		return "validation_error"
	case strings.Contains(msg, "not_found") || strings.Contains(msg, "not found"):
		return "not_found"
	case strings.Contains(msg, "revoked") || strings.Contains(msg, "no linked credentials"):
		return "auth_invalid"
	case strings.Contains(msg, "runtime metadata") || strings.Contains(msg, "incompatible"):
		return "auth_profile_incompatible"
	case strings.Contains(msg, "failed to update"):
		return "store_error"
	default:
		return "unknown_error"
	}
}

// cloudAuthRevokeStoreFactory is a package-level variable that tests can override.
var cloudAuthRevokeStoreFactory func() (cloud.Store, error)

// cloudAuthRevokeResponse is the JSON output for a successful auth revoke.
type cloudAuthRevokeResponse struct {
	ProfileID string `json:"profile_id"`
	Provider  string `json:"provider"`
	Status    string `json:"status"`
	RevokedAt string `json:"revoked_at"`
}

// runCloudAuthRevoke is the testable logic for the cloud auth revoke command.
func runCloudAuthRevoke(
	profileID string,
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

	svc := cloud.NewAuthRevokeService(store, cloud.AuthRevokeConfig{})

	req := &cloud.AuthRevokeRequest{
		ProfileID: profileID,
	}

	ctx := context.Background()
	result, err := svc.Revoke(ctx, req)
	if err != nil {
		code := classifyAuthRevokeError(err)
		if jsonOutput {
			_ = writeJSON(out, cloudErrorResponse{
				Error:     err.Error(),
				ErrorCode: code,
			})
			return fmt.Errorf("auth revoke failed: %w", err)
		}
		return fmt.Errorf("auth revoke failed: %w", err)
	}

	if jsonOutput {
		return writeJSON(out, cloudAuthRevokeResponse{
			ProfileID: result.ProfileID,
			Provider:  result.Provider,
			Status:    result.Status,
			RevokedAt: result.RevokedAt.Format(time.RFC3339),
		})
	}

	fmt.Fprintf(out, "Auth profile revoked.\n")
	fmt.Fprintf(out, "  profile_id: %s\n", result.ProfileID)
	fmt.Fprintf(out, "  provider:   %s\n", result.Provider)
	fmt.Fprintf(out, "  status:     %s\n", result.Status)
	fmt.Fprintf(out, "  revoked_at: %s\n", result.RevokedAt.Format(time.RFC3339))
	return nil
}

// classifyAuthRevokeError maps service errors to machine-readable error codes.
func classifyAuthRevokeError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()

	switch {
	case strings.Contains(msg, "must not be empty") || strings.Contains(msg, "validation failed"):
		return "validation_error"
	case strings.Contains(msg, "not_found") || strings.Contains(msg, "not found"):
		return "not_found"
	case strings.Contains(msg, "failed to update"):
		return "store_error"
	default:
		return "unknown_error"
	}
}
