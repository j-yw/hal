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
		{"sandbox-list-v1", "../docs/contracts/sandbox-list-v1.md"},
		{"auto-v2", "../docs/contracts/auto-v2.md"},
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

// TestContractDocsIncludeSandboxListFields verifies that sandbox-list-v1 contract
// docs list all required field names from the code types.
func TestContractDocsIncludeSandboxListFields(t *testing.T) {
	data, err := os.ReadFile("../docs/contracts/sandbox-list-v1.md")
	if err != nil {
		t.Skipf("cannot read sandbox-list-v1.md: %v", err)
	}
	content := string(data)

	// Top-level required fields
	topLevelFields := []string{"contractVersion", "sandboxes", "totals"}
	for _, f := range topLevelFields {
		if !strings.Contains(content, f) {
			t.Errorf("sandbox-list-v1.md missing top-level field %q", f)
		}
	}

	// Sandbox entry required fields
	entryRequiredFields := []string{"id", "name", "provider", "status", "createdAt"}
	for _, f := range entryRequiredFields {
		if !strings.Contains(content, "`"+f+"`") {
			t.Errorf("sandbox-list-v1.md missing sandbox entry required field %q", f)
		}
	}

	// Sandbox entry optional fields
	entryOptionalFields := []string{
		"workspaceId", "ip", "tailscaleIp", "tailscaleHostname",
		"stoppedAt", "autoShutdown", "idleHours", "size",
		"repo", "snapshotId", "estimatedCost",
	}
	for _, f := range entryOptionalFields {
		if !strings.Contains(content, "`"+f+"`") {
			t.Errorf("sandbox-list-v1.md missing sandbox entry optional field %q", f)
		}
	}

	// Totals fields
	totalsFields := []string{"total", "running", "stopped"}
	for _, f := range totalsFields {
		if !strings.Contains(content, "`"+f+"`") {
			t.Errorf("sandbox-list-v1.md missing totals field %q", f)
		}
	}

	// Contract version value
	if !strings.Contains(content, "sandbox-list-v1") {
		t.Error("sandbox-list-v1.md missing contract version value \"sandbox-list-v1\"")
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

func TestContractDocsIncludeAutoV2Fields(t *testing.T) {
	data, err := os.ReadFile("../docs/contracts/auto-v2.md")
	if err != nil {
		t.Skipf("cannot read auto-v2.md: %v", err)
	}
	content := string(data)

	requiredTopLevelFields := []string{"contractVersion", "ok", "entryMode", "resumed", "steps", "summary"}
	for _, f := range requiredTopLevelFields {
		if !strings.Contains(content, "`"+f+"`") {
			t.Errorf("auto-v2.md missing required top-level field %q", f)
		}
	}

	requiredStepKeys := []string{"analyze", "spec", "branch", "convert", "validate", "run", "review", "report", "ci", "archive"}
	for _, step := range requiredStepKeys {
		if !strings.Contains(content, "`"+step+"`") {
			t.Errorf("auto-v2.md missing required step key %q", step)
		}
	}

	requiredStatuses := []string{"completed", "skipped", "failed", "pending"}
	for _, status := range requiredStatuses {
		if !strings.Contains(content, "`"+status+"`") {
			t.Errorf("auto-v2.md missing step status enum %q", status)
		}
	}

	if !strings.Contains(content, "Contract Version:** 2") {
		t.Error("auto-v2.md missing contract version declaration for v2")
	}
}

func TestContractDocsIncludeAutoV2Examples(t *testing.T) {
	successPath := "../docs/contracts/examples/auto-v2-success.json"
	failurePath := "../docs/contracts/examples/auto-v2-failure.json"

	if _, err := os.Stat(successPath); os.IsNotExist(err) {
		t.Fatalf("auto v2 success example is missing at %s", successPath)
	}
	if _, err := os.Stat(failurePath); os.IsNotExist(err) {
		t.Fatalf("auto v2 failure example is missing at %s", failurePath)
	}

	data, err := os.ReadFile("../docs/contracts/auto-v2.md")
	if err != nil {
		t.Skipf("cannot read auto-v2.md: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "auto-v2-success.json") {
		t.Error("auto-v2.md should reference auto-v2-success.json")
	}
	if !strings.Contains(content, "auto-v2-failure.json") {
		t.Error("auto-v2.md should reference auto-v2-failure.json")
	}
}
