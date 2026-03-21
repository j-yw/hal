package sandbox

import (
	"strings"
	"testing"
)

func TestValidateName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:  "valid simple name",
			input: "api-backend",
		},
		{
			name:  "valid with digits",
			input: "worker-01",
		},
		{
			name:  "valid boundary length",
			input: strings.Repeat("a", 59),
		},
		{
			name:    "empty name",
			input:   "",
			wantErr: "must be 1-59 chars",
		},
		{
			name:    "too long",
			input:   strings.Repeat("a", 60),
			wantErr: "must be 1-59 chars",
		},
		{
			name:    "uppercase letters",
			input:   "MyServer",
			wantErr: "must be lowercase alphanumeric and hyphens",
		},
		{
			name:    "special characters",
			input:   "my_server!",
			wantErr: "must be lowercase alphanumeric and hyphens",
		},
		{
			name:    "leading hyphen",
			input:   "-server",
			wantErr: "must not start or end with hyphen",
		},
		{
			name:    "trailing hyphen",
			input:   "server-",
			wantErr: "must not start or end with hyphen",
		},
		{
			name:    "consecutive hyphens",
			input:   "server--api",
			wantErr: "must not contain consecutive hyphens",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateName(tt.input)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tt.wantErr)
				}
				if err.Error() != tt.wantErr {
					t.Fatalf("ValidateName(%q) error = %q, want %q", tt.input, err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateName(%q) unexpected error: %v", tt.input, err)
			}
		})
	}
}

func TestTailscaleHostname(t *testing.T) {
	if got := TailscaleHostname("api-backend"); got != "hal-api-backend" {
		t.Fatalf("TailscaleHostname() = %q, want %q", got, "hal-api-backend")
	}
}

func TestSandboxNameFromBranch(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "slashes become hyphens",
			input: "hal/feature-auth",
			want:  "hal-feature-auth",
		},
		{
			name:  "normalizes uppercase and underscores",
			input: "Feature/Auth_OAuth",
			want:  "feature-auth-oauth",
		},
		{
			name:  "trims and collapses separators",
			input: "  /team//My Branch/  ",
			want:  "team-my-branch",
		},
		{
			name:  "backslashes become hyphens",
			input: "back\\slash",
			want:  "back-slash",
		},
		{
			name:  "falls back for fully invalid branch",
			input: "!!!",
			want:  "sandbox",
		},
		{
			name:  "truncates to maximum valid length",
			input: strings.Repeat("a", 70),
			want:  strings.Repeat("a", 59),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SandboxNameFromBranch(tt.input)
			if got != tt.want {
				t.Fatalf("SandboxNameFromBranch(%q) = %q, want %q", tt.input, got, tt.want)
			}
			if err := ValidateName(got); err != nil {
				t.Fatalf("SandboxNameFromBranch(%q) produced invalid name %q: %v", tt.input, got, err)
			}
		})
	}
}
