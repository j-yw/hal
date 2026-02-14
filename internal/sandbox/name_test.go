package sandbox

import "testing"

func TestSandboxNameFromBranch(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hal/feature-auth", "hal-feature-auth"},
		{"feature/auth/oauth", "feature-auth-oauth"},
		{"main", "main"},
		{"hal/sandbox-implementation", "hal-sandbox-implementation"},
		{"  hal/spaces  ", "hal-spaces"},
		{"back\\slash", "back-slash"},
		{"no-change", "no-change"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := SandboxNameFromBranch(tt.input)
			if got != tt.want {
				t.Errorf("SandboxNameFromBranch(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
