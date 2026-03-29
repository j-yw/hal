package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/ci"
	"github.com/jywlabs/hal/internal/doctor"
	"github.com/jywlabs/hal/internal/status"
	"github.com/jywlabs/hal/internal/template"
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
		{"ci-push-v1", "../docs/contracts/ci-push-v1.md"},
		{"ci-status-v1", "../docs/contracts/ci-status-v1.md"},
		{"ci-fix-v1", "../docs/contracts/ci-fix-v1.md"},
		{"ci-merge-v1", "../docs/contracts/ci-merge-v1.md"},
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

	// Run doctor in a repo with .hal present so all checks are emitted.
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(halDir, template.ConfigFile), []byte("engine: pi\n"), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	result := doctor.Run(doctor.Options{Dir: dir, Engine: "pi"})

	for _, check := range result.Checks {
		if !strings.Contains(content, check.ID) {
			t.Errorf("doctor-v1.md missing check ID %q", check.ID)
		}
	}
}

func TestContractDocsIncludeCIFields(t *testing.T) {
	docs := []struct {
		name           string
		path           string
		contractValue  string
		requiredFields []string
		requiredValues []string
	}{
		{
			name:          "ci-push-v1",
			path:          "../docs/contracts/ci-push-v1.md",
			contractValue: ci.PushContractVersion,
			requiredFields: []string{
				"contractVersion", "branch", "pushed", "dryRun", "pullRequest", "summary",
				"number", "url", "title", "headRef", "headSha", "baseRef", "draft", "existing",
			},
		},
		{
			name:          "ci-status-v1",
			path:          "../docs/contracts/ci-status-v1.md",
			contractValue: ci.StatusContractVersion,
			requiredFields: []string{
				"contractVersion", "branch", "sha", "status", "checksDiscovered", "wait", "waitTerminalReason", "checks", "totals", "summary",
				"key", "source", "name", "url", "pending", "failing", "passing",
			},
			requiredValues: []string{
				ci.StatusPending,
				ci.StatusFailing,
				ci.StatusPassing,
				ci.WaitTerminalReasonCompleted,
				ci.WaitTerminalReasonTimeout,
				ci.WaitTerminalReasonNoChecksDetected,
				ci.CheckSourceCheckRun,
				ci.CheckSourceStatus,
			},
		},
		{
			name:          "ci-fix-v1",
			path:          "../docs/contracts/ci-fix-v1.md",
			contractValue: ci.FixContractVersion,
			requiredFields: []string{
				"contractVersion", "attempt", "maxAttempts", "applied", "branch", "commitSha", "pushed", "filesChanged", "summary",
			},
		},
		{
			name:          "ci-merge-v1",
			path:          "../docs/contracts/ci-merge-v1.md",
			contractValue: ci.MergeContractVersion,
			requiredFields: []string{
				"contractVersion", "prNumber", "strategy", "dryRun", "merged", "mergeCommitSha", "branchDeleted", "deleteWarning", "summary",
			},
		},
	}

	for _, doc := range docs {
		t.Run(doc.name, func(t *testing.T) {
			data, err := os.ReadFile(doc.path)
			if err != nil {
				t.Fatalf("cannot read %s: %v", doc.path, err)
			}
			content := string(data)

			if !strings.Contains(content, doc.contractValue) {
				t.Errorf("%s missing contract value %q", doc.name, doc.contractValue)
			}

			for _, field := range doc.requiredFields {
				if !strings.Contains(content, "`"+field+"`") {
					t.Errorf("%s missing field %q", doc.name, field)
				}
			}

			for _, value := range doc.requiredValues {
				if !strings.Contains(content, value) {
					t.Errorf("%s missing value %q", doc.name, value)
				}
			}
		})
	}
}
