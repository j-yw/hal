package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
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

var cloudAuthCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage auth profiles",
	Long: `Manage auth profiles for cloud orchestration.

Commands:
  link        Link an auth profile to a provider
  import      Import local auth artifacts into a profile`,
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

	cloudAuthCmd.AddCommand(cloudAuthLinkCmd)
	cloudAuthCmd.AddCommand(cloudAuthImportCmd)
	cloudCmd.AddCommand(cloudAuthCmd)
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
	out io.Writer,
) error {
	if storeFactory == nil {
		return writeCloudError(out, jsonOutput, "store not configured", "configuration_error")
	}

	store, err := storeFactory()
	if err != nil {
		return writeCloudError(out, jsonOutput, fmt.Sprintf("failed to connect to store: %v", err), "configuration_error")
	}

	svc := cloud.NewAuthImportService(store, cloud.AuthImportConfig{})

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
	case strings.Contains(msg, "already exists"):
		return "duplicate_profile"
	case strings.Contains(msg, "failed to create"):
		return "store_error"
	default:
		return "unknown_error"
	}
}
