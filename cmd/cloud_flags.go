package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// CloudFlags holds the values of the shared cloud flag set. These flags are
// registered on hal run, hal auto, and hal review to provide a uniform cloud
// execution interface.
type CloudFlags struct {
	Cloud            bool
	CloudProfile     string
	Detach           bool
	Wait             bool
	JSON             bool
	CloudMode        string
	CloudEndpoint    string
	CloudRepo        string
	CloudBase        string
	CloudAuthProfile string
	CloudAuthScope   string
}

// RegisterCloudFlags registers the shared cloud flag set on the given command.
// The returned CloudFlags struct is populated when the command is executed.
func RegisterCloudFlags(cmd *cobra.Command) *CloudFlags {
	f := &CloudFlags{}
	cmd.Flags().BoolVar(&f.Cloud, "cloud", false, "Execute in the cloud")
	cmd.Flags().StringVar(&f.CloudProfile, "cloud-profile", "", "Cloud profile name from .hal/cloud.yaml")
	cmd.Flags().BoolVar(&f.Detach, "detach", false, "Submit and return immediately without waiting")
	cmd.Flags().BoolVar(&f.Wait, "wait", false, "Wait for cloud run to complete")
	cmd.Flags().BoolVar(&f.JSON, "json", false, "Output in JSON format")
	cmd.Flags().StringVar(&f.CloudMode, "cloud-mode", "", "Cloud execution mode")
	cmd.Flags().StringVar(&f.CloudEndpoint, "cloud-endpoint", "", "Cloud endpoint URL")
	cmd.Flags().StringVar(&f.CloudRepo, "cloud-repo", "", "Repository (owner/repo)")
	cmd.Flags().StringVar(&f.CloudBase, "cloud-base", "", "Base branch name")
	cmd.Flags().StringVar(&f.CloudAuthProfile, "cloud-auth-profile", "", "Auth profile ID")
	cmd.Flags().StringVar(&f.CloudAuthScope, "cloud-auth-scope", "", "Auth scope reference")
	return f
}

// CloudFlagError represents a deterministic error from cloud flag validation.
type CloudFlagError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *CloudFlagError) Error() string {
	return e.Message
}

// ValidateCloudFlags checks cloud flag combinations for conflicts.
// Returns a *CloudFlagError with code "invalid_flag_combination" if
// --detach and --wait are both set.
func ValidateCloudFlags(f *CloudFlags) error {
	if f.Detach && f.Wait {
		return &CloudFlagError{
			Code:    "invalid_flag_combination",
			Message: fmt.Sprintf("--detach and --wait cannot be used together"),
		}
	}
	return nil
}

// CloudFlagNames returns the list of shared cloud flag names for documentation
// and help text verification.
func CloudFlagNames() []string {
	return []string{
		"cloud",
		"cloud-profile",
		"detach",
		"wait",
		"json",
		"cloud-mode",
		"cloud-endpoint",
		"cloud-repo",
		"cloud-base",
		"cloud-auth-profile",
		"cloud-auth-scope",
	}
}
