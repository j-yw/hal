package cloud

import (
	"strings"
	"testing"
)

func TestWorkingBranch(t *testing.T) {
	tests := []struct {
		runID string
		want  string
	}{
		{"run-abc123", "hal/cloud/run-abc123"},
		{"run-00000000", "hal/cloud/run-00000000"},
		{"x", "hal/cloud/x"},
	}

	for _, tt := range tests {
		t.Run(tt.runID, func(t *testing.T) {
			got := WorkingBranch(tt.runID)
			if got != tt.want {
				t.Errorf("WorkingBranch(%q) = %q, want %q", tt.runID, got, tt.want)
			}
			if !strings.HasPrefix(got, WorkingBranchPrefix) {
				t.Errorf("WorkingBranch(%q) does not start with prefix %q", tt.runID, WorkingBranchPrefix)
			}
		})
	}
}

func TestWorkingBranchUniqueness(t *testing.T) {
	a := WorkingBranch("run-001")
	b := WorkingBranch("run-002")
	if a == b {
		t.Errorf("different run IDs should produce different branches: %q == %q", a, b)
	}
}
