package cmd

import (
	"os"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/doctor"
	"github.com/jywlabs/hal/internal/status"
)

// TestContractDocsExist verifies that contract documentation exists for
// every machine-readable command surface. This prevents shipping new
// contracts without documentation.
func TestContractDocsExist(t *testing.T) {
	// Contract docs are in the repo root; cmd tests run from cmd/ directory
	requiredDocs := []struct {
		name string
		path string
	}{
		{"status-v1", "../docs/contracts/status-v1.md"},
		{"doctor-v1", "../docs/contracts/doctor-v1.md"},
		{"continue-v1", "../docs/contracts/continue-v1.md"},
	}

	for _, doc := range requiredDocs {
		t.Run(doc.name, func(t *testing.T) {
			if _, err := os.Stat(doc.path); os.IsNotExist(err) {
				t.Fatalf("contract doc %s is missing at %s", doc.name, doc.path)
			}
		})
	}
}

// TestContractDocsIncludeStateValues verifies that status contract docs
// list all state values defined in the code.
func TestContractDocsIncludeStateValues(t *testing.T) {
	data, err := os.ReadFile("../docs/contracts/status-v1.md")
	if err != nil {
		t.Skipf("cannot read status-v1.md: %v", err)
	}
	content := string(data)

	states := []string{
		status.StateNotInitialized,
		status.StateInitializedNoPRD,
		status.StateManualInProgress,
		status.StateManualComplete,
		status.StateCompoundActive,
		status.StateCompoundComplete,
		status.StateReviewLoopComplete,
	}

	for _, state := range states {
		if !strings.Contains(content, state) {
			t.Errorf("status-v1.md missing state value %q", state)
		}
	}
}

// TestContractDocsIncludeCheckIDs verifies that doctor contract docs
// list all check IDs defined in the code.
func TestContractDocsIncludeCheckIDs(t *testing.T) {
	data, err := os.ReadFile("../docs/contracts/doctor-v1.md")
	if err != nil {
		t.Skipf("cannot read doctor-v1.md: %v", err)
	}
	content := string(data)

	// Run doctor to get check IDs
	dir := t.TempDir()
	result := doctor.Run(doctor.Options{Dir: dir, Engine: "codex"})

	for _, check := range result.Checks {
		if !strings.Contains(content, check.ID) {
			t.Errorf("doctor-v1.md missing check ID %q", check.ID)
		}
	}
}
