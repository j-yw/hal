package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRegisterCloudFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	flags := RegisterCloudFlags(cmd)

	if flags == nil {
		t.Fatal("RegisterCloudFlags returned nil")
	}

	// Verify all expected flags are registered.
	expectedFlags := CloudFlagNames()
	for _, name := range expectedFlags {
		f := cmd.Flags().Lookup(name)
		if f == nil {
			t.Errorf("expected flag %q to be registered, but it was not", name)
		}
	}
}

func TestRegisterCloudFlags_DefaultValues(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	flags := RegisterCloudFlags(cmd)

	// Bool flags default to false.
	if flags.Cloud {
		t.Error("Cloud should default to false")
	}
	if flags.Detach {
		t.Error("Detach should default to false")
	}
	if flags.Wait {
		t.Error("Wait should default to false")
	}
	if flags.JSON {
		t.Error("JSON should default to false")
	}

	// String flags default to empty.
	if flags.CloudProfile != "" {
		t.Errorf("CloudProfile should default to empty, got %q", flags.CloudProfile)
	}
	if flags.CloudMode != "" {
		t.Errorf("CloudMode should default to empty, got %q", flags.CloudMode)
	}
	if flags.CloudEndpoint != "" {
		t.Errorf("CloudEndpoint should default to empty, got %q", flags.CloudEndpoint)
	}
	if flags.CloudRepo != "" {
		t.Errorf("CloudRepo should default to empty, got %q", flags.CloudRepo)
	}
	if flags.CloudBase != "" {
		t.Errorf("CloudBase should default to empty, got %q", flags.CloudBase)
	}
	if flags.CloudAuthProfile != "" {
		t.Errorf("CloudAuthProfile should default to empty, got %q", flags.CloudAuthProfile)
	}
	if flags.CloudAuthScope != "" {
		t.Errorf("CloudAuthScope should default to empty, got %q", flags.CloudAuthScope)
	}
}

func TestRegisterCloudFlags_ParsesValues(t *testing.T) {
	cmd := &cobra.Command{Use: "test", RunE: func(cmd *cobra.Command, args []string) error { return nil }}
	flags := RegisterCloudFlags(cmd)

	cmd.SetArgs([]string{
		"--cloud",
		"--cloud-profile", "production",
		"--detach",
		"--json",
		"--cloud-mode", "until_complete",
		"--cloud-endpoint", "https://cloud.example.com",
		"--cloud-repo", "owner/repo",
		"--cloud-base", "develop",
		"--cloud-auth-profile", "my-auth",
		"--cloud-auth-scope", "full",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("command execution failed: %v", err)
	}

	if !flags.Cloud {
		t.Error("expected Cloud to be true")
	}
	if flags.CloudProfile != "production" {
		t.Errorf("expected CloudProfile %q, got %q", "production", flags.CloudProfile)
	}
	if !flags.Detach {
		t.Error("expected Detach to be true")
	}
	if !flags.JSON {
		t.Error("expected JSON to be true")
	}
	if flags.CloudMode != "until_complete" {
		t.Errorf("expected CloudMode %q, got %q", "until_complete", flags.CloudMode)
	}
	if flags.CloudEndpoint != "https://cloud.example.com" {
		t.Errorf("expected CloudEndpoint %q, got %q", "https://cloud.example.com", flags.CloudEndpoint)
	}
	if flags.CloudRepo != "owner/repo" {
		t.Errorf("expected CloudRepo %q, got %q", "owner/repo", flags.CloudRepo)
	}
	if flags.CloudBase != "develop" {
		t.Errorf("expected CloudBase %q, got %q", "develop", flags.CloudBase)
	}
	if flags.CloudAuthProfile != "my-auth" {
		t.Errorf("expected CloudAuthProfile %q, got %q", "my-auth", flags.CloudAuthProfile)
	}
	if flags.CloudAuthScope != "full" {
		t.Errorf("expected CloudAuthScope %q, got %q", "full", flags.CloudAuthScope)
	}
}

func TestValidateCloudFlags(t *testing.T) {
	tests := []struct {
		name    string
		flags   *CloudFlags
		wantErr string
		errCode string
	}{
		{
			name:  "no conflict - both false",
			flags: &CloudFlags{},
		},
		{
			name:  "no conflict - only detach",
			flags: &CloudFlags{Detach: true},
		},
		{
			name:  "no conflict - only wait",
			flags: &CloudFlags{Wait: true},
		},
		{
			name:    "conflict - both detach and wait",
			flags:   &CloudFlags{Detach: true, Wait: true},
			wantErr: "--detach and --wait cannot be used together",
			errCode: "invalid_flag_combination",
		},
		{
			name:    "conflict - detach and wait with other flags set",
			flags:   &CloudFlags{Cloud: true, Detach: true, Wait: true, JSON: true, CloudProfile: "prod"},
			wantErr: "--detach and --wait cannot be used together",
			errCode: "invalid_flag_combination",
		},
		{
			name:  "no conflict - cloud with other flags",
			flags: &CloudFlags{Cloud: true, JSON: true, CloudMode: "until_complete", CloudEndpoint: "https://example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCloudFlags(tt.flags)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}

				// Verify deterministic error code.
				var cfe *CloudFlagError
				if !errors.As(err, &cfe) {
					t.Fatalf("expected *CloudFlagError, got %T", err)
				}
				if cfe.Code != tt.errCode {
					t.Errorf("expected error code %q, got %q", tt.errCode, cfe.Code)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCloudFlagError_Implements_Error(t *testing.T) {
	err := &CloudFlagError{
		Code:    "invalid_flag_combination",
		Message: "--detach and --wait cannot be used together",
	}

	// Verify it implements the error interface.
	var e error = err
	if e.Error() != "--detach and --wait cannot be used together" {
		t.Errorf("unexpected error message: %q", e.Error())
	}
}

func TestCloudFlagError_ErrorsAs(t *testing.T) {
	err := ValidateCloudFlags(&CloudFlags{Detach: true, Wait: true})
	if err == nil {
		t.Fatal("expected error")
	}

	var cfe *CloudFlagError
	if !errors.As(err, &cfe) {
		t.Fatal("expected errors.As to match *CloudFlagError")
	}
	if cfe.Code != "invalid_flag_combination" {
		t.Errorf("expected code %q, got %q", "invalid_flag_combination", cfe.Code)
	}
}

func TestCloudFlagNames(t *testing.T) {
	names := CloudFlagNames()

	expected := []string{
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

	if len(names) != len(expected) {
		t.Fatalf("expected %d flag names, got %d", len(expected), len(names))
	}

	for i, name := range names {
		if name != expected[i] {
			t.Errorf("flag name[%d]: expected %q, got %q", i, expected[i], name)
		}
	}
}

func TestRegisterCloudFlags_MultipleCommands(t *testing.T) {
	// Verify that RegisterCloudFlags can be called on multiple commands
	// independently (simulating registration on run, auto, review).
	cmds := []*cobra.Command{
		{Use: "run"},
		{Use: "auto"},
		{Use: "review"},
	}

	flagSets := make([]*CloudFlags, len(cmds))
	for i, cmd := range cmds {
		flagSets[i] = RegisterCloudFlags(cmd)
	}

	// Verify each command has all flags.
	for _, cmd := range cmds {
		for _, name := range CloudFlagNames() {
			if cmd.Flags().Lookup(name) == nil {
				t.Errorf("command %q missing flag %q", cmd.Use, name)
			}
		}
	}

	// Verify flag values are independent.
	flagSets[0].Cloud = true
	if flagSets[1].Cloud {
		t.Error("flag values should be independent across commands")
	}
}
