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

func TestBatchNames(t *testing.T) {
	boundaryBase := strings.Repeat("a", 56)
	tests := []struct {
		name          string
		base          string
		count         int
		want          []string
		wantLen       int
		wantFirst     string
		wantLast      string
		wantErrSubstr string
	}{
		{
			name:  "count 5 uses two-digit padding",
			base:  "worker",
			count: 5,
			want:  []string{"worker-01", "worker-02", "worker-03", "worker-04", "worker-05"},
		},
		{
			name:      "count 100 uses three-digit padding",
			base:      "worker",
			count:     100,
			wantLen:   100,
			wantFirst: "worker-001",
			wantLast:  "worker-100",
		},
		{
			name:          "count less than one returns error",
			base:          "worker",
			count:         0,
			wantErrSubstr: "count must be at least 1",
		},
		{
			name:          "base plus suffix longer than limit returns error",
			base:          strings.Repeat("a", 57),
			count:         5,
			wantErrSubstr: "exceeds 59 chars",
		},
		{
			name:          "invalid generated name is rejected",
			base:          "Worker",
			count:         3,
			wantErrSubstr: "must be lowercase alphanumeric and hyphens",
		},
		{
			name:      "max boundary with suffix succeeds",
			base:      boundaryBase,
			count:     5,
			wantLen:   5,
			wantFirst: boundaryBase + "-01",
			wantLast:  boundaryBase + "-05",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BatchNames(tt.base, tt.count)
			if tt.wantErrSubstr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErrSubstr)
				}
				if !strings.Contains(err.Error(), tt.wantErrSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErrSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("BatchNames(%q, %d) unexpected error: %v", tt.base, tt.count, err)
			}
			if tt.want != nil {
				if len(got) != len(tt.want) {
					t.Fatalf("BatchNames(%q, %d) len = %d, want %d", tt.base, tt.count, len(got), len(tt.want))
				}
				for i := range tt.want {
					if got[i] != tt.want[i] {
						t.Fatalf("BatchNames(%q, %d)[%d] = %q, want %q", tt.base, tt.count, i, got[i], tt.want[i])
					}
				}
			}
			if tt.wantLen > 0 && len(got) != tt.wantLen {
				t.Fatalf("BatchNames(%q, %d) len = %d, want %d", tt.base, tt.count, len(got), tt.wantLen)
			}
			if tt.wantFirst != "" && got[0] != tt.wantFirst {
				t.Fatalf("BatchNames(%q, %d) first = %q, want %q", tt.base, tt.count, got[0], tt.wantFirst)
			}
			if tt.wantLast != "" && got[len(got)-1] != tt.wantLast {
				t.Fatalf("BatchNames(%q, %d) last = %q, want %q", tt.base, tt.count, got[len(got)-1], tt.wantLast)
			}
			for _, name := range got {
				if err := ValidateName(name); err != nil {
					t.Fatalf("BatchNames(%q, %d) produced invalid name %q: %v", tt.base, tt.count, name, err)
				}
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
