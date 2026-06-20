package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/ci"
	"github.com/jywlabs/hal/internal/doctor"
	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/status"
	"github.com/jywlabs/hal/internal/template"
	"github.com/jywlabs/hal/internal/verify"
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
		{"plan-v1", "../docs/contracts/plan-v1.md"},
		{"sandbox-list-v1", "../docs/contracts/sandbox-list-v1.md"},
		{"auto-v2", "../docs/contracts/auto-v2.md"},
		{"ci-push-v1", "../docs/contracts/ci-push-v1.md"},
		{"ci-status-v1", "../docs/contracts/ci-status-v1.md"},
		{"ci-fix-v1", "../docs/contracts/ci-fix-v1.md"},
		{"ci-merge-v1", "../docs/contracts/ci-merge-v1.md"},
		{"factory-run-v1", "../docs/contracts/factory-run-v1.md"},
		{"factory-list-v1", "../docs/contracts/factory-list-v1.md"},
		{"factory-status-v1", "../docs/contracts/factory-status-v1.md"},
		{"factory-timeline-v1", "../docs/contracts/factory-timeline-v1.md"},
		{"verify-v1", "../docs/contracts/verify-v1.md"},
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

func TestContractDocsIncludePlanV1Fields(t *testing.T) {
	data, err := os.ReadFile("../docs/contracts/plan-v1.md")
	if err != nil {
		t.Skipf("cannot read plan-v1.md: %v", err)
	}
	content := string(data)

	requiredFields := []string{"contractVersion", "ok", "outputPath", "format", "inputSource", "questionsAsked", "nextSteps", "error", "summary"}
	for _, f := range requiredFields {
		if !strings.Contains(content, "`"+f+"`") {
			t.Errorf("plan-v1.md missing field %q", f)
		}
	}
	for _, value := range []string{PlanInputSourceArgument, PlanInputSourceFile, PlanInputSourceStdin, PlanInputSourceEditor, "markdown", "json"} {
		if !strings.Contains(content, "`"+value+"`") && !strings.Contains(content, "\""+value+"\"") {
			t.Errorf("plan-v1.md missing value %q", value)
		}
	}
	if !strings.Contains(content, "Contract Version:** 1") {
		t.Error("plan-v1.md missing numeric contract version declaration")
	}
}

func TestContractDocsIncludePlanV1Examples(t *testing.T) {
	successPath := "../docs/contracts/examples/plan-v1-success.json"
	failurePath := "../docs/contracts/examples/plan-v1-failure.json"

	if _, err := os.Stat(successPath); os.IsNotExist(err) {
		t.Fatalf("plan v1 success example is missing at %s", successPath)
	}
	if _, err := os.Stat(failurePath); os.IsNotExist(err) {
		t.Fatalf("plan v1 failure example is missing at %s", failurePath)
	}

	data, err := os.ReadFile("../docs/contracts/plan-v1.md")
	if err != nil {
		t.Skipf("cannot read plan-v1.md: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "plan-v1-success.json") {
		t.Error("plan-v1.md should reference plan-v1-success.json")
	}
	if !strings.Contains(content, "plan-v1-failure.json") {
		t.Error("plan-v1.md should reference plan-v1-failure.json")
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

func TestContractDocsIncludeVerifyV1Fields(t *testing.T) {
	data, err := os.ReadFile("../docs/contracts/verify-v1.md")
	if err != nil {
		t.Skipf("cannot read verify-v1.md: %v", err)
	}
	content := string(data)

	requiredFields := []string{
		"schemaVersion", "generatedAt", "status", "summary", "checks", "warnings", "artifacts",
		"total", "passed", "failed", "timedOut", "missing", "skipped",
		"id", "name", "adapter", "required", "command", "workDir", "timeoutSeconds",
		"startedAt", "finishedAt", "durationMs", "exitCode", "stdoutArtifact", "stderrArtifact", "message",
		"checkId", "kind", "path",
	}
	for _, field := range requiredFields {
		if !strings.Contains(content, "`"+field+"`") {
			t.Errorf("verify-v1.md missing field %q", field)
		}
	}

	requiredValues := []string{
		verify.SchemaVersion,
		verify.StatusPass,
		verify.StatusFail,
		verify.StatusWarn,
		verify.CheckStatusPass,
		verify.CheckStatusFail,
		verify.CheckStatusTimeout,
		verify.CheckStatusMissing,
		verify.CheckStatusSkipped,
		verify.AdapterShell,
	}
	for _, value := range requiredValues {
		if !strings.Contains(content, value) {
			t.Errorf("verify-v1.md missing value %q", value)
		}
	}

	if !strings.Contains(content, "Required check failures and timeouts produce a failing gate") {
		t.Error("verify-v1.md missing required failure/timeout gate behavior")
	}
}

func TestContractDocsIncludeVerifyV1Examples(t *testing.T) {
	examples := []string{
		"verify-v1-pass.json",
		"verify-v1-fail.json",
		"verify-v1-warn.json",
	}

	data, err := os.ReadFile("../docs/contracts/verify-v1.md")
	if err != nil {
		t.Skipf("cannot read verify-v1.md: %v", err)
	}
	content := string(data)

	for _, example := range examples {
		path := filepath.Join("..", "docs", "contracts", "examples", example)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Fatalf("verify-v1 example is missing at %s", path)
		}
		if !strings.Contains(content, example) {
			t.Errorf("verify-v1.md should reference %s", example)
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

func TestContractDocsIncludeFactoryFields(t *testing.T) {
	docs := []struct {
		name           string
		path           string
		contractValue  string
		requiredFields []string
		requiredValues []string
	}{
		{
			name:          "factory-run-v1",
			path:          "../docs/contracts/factory-run-v1.md",
			contractValue: FactoryRunContractVersion,
			requiredFields: []string{
				"contractVersion", "version", "runId", "status", "nextAction", "artifacts",
				"eventSummary", "failure", "id", "command", "description", "total", "byType",
				"lastEventType", "lastSummary", "classification", "errorMessage", "suggestedCommand",
			},
			requiredValues: []string{
				factory.RunStatusPending,
				factory.RunStatusRunning,
				factory.RunStatusSucceeded,
				factory.RunStatusFailed,
				factory.RunStatusCanceled,
				factory.EventTypeRunCreated,
				factory.EventTypeFailureClassification,
				"validation",
				"pipeline",
				"engine",
				"git",
				"ci",
				"unknown",
			},
		},
		{
			name:          "factory-list-v1",
			path:          "../docs/contracts/factory-list-v1.md",
			contractValue: FactoryListContractVersion,
			requiredFields: []string{
				"contractVersion", "runs", "runId", "status", "source", "repoPath", "repoRemote",
				"branchName", "baseBranch", "sandboxName", "currentStep", "createdAt", "updatedAt",
				"finishedAt", "artifactCount", "failure", "suggestedCommand",
			},
			requiredValues: []string{
				factory.RunStatusPending,
				factory.RunStatusRunning,
				factory.RunStatusSucceeded,
				factory.RunStatusFailed,
				factory.RunStatusCanceled,
				factory.FailureCategoryValidation,
				factory.FailureCategoryPipeline,
				factory.FailureCategoryEngine,
				factory.FailureCategoryGit,
				factory.FailureCategoryCI,
				factory.FailureCategoryUnknown,
			},
		},
		{
			name:          "factory-status-v1",
			path:          "../docs/contracts/factory-status-v1.md",
			contractValue: FactoryStatusContractVersion,
			requiredFields: []string{
				"contractVersion", "run", "timeline", "runId", "status", "executorMode", "source", "repoPath", "repoRemote",
				"branchName", "baseBranch", "sandboxName", "currentStep", "createdAt", "updatedAt",
				"finishedAt", "artifacts", "verification", "summary", "total", "passed", "failed", "timedOut",
				"missing", "skipped", "warnings", "checkId", "kind", "failure", "suggestedCommand",
			},
			requiredValues: []string{
				factory.RunStatusPending,
				factory.RunStatusRunning,
				factory.RunStatusSucceeded,
				factory.RunStatusFailed,
				factory.RunStatusCanceled,
				factory.FailureCategoryValidation,
				factory.FailureCategoryPipeline,
				factory.FailureCategoryEngine,
				factory.FailureCategoryGit,
				factory.FailureCategoryCI,
				factory.FailureCategoryUnknown,
				verify.ArtifactKindStdout,
				verify.ArtifactKindStderr,
			},
		},
		{
			name:          "factory-timeline-v1",
			path:          "../docs/contracts/factory-timeline-v1.md",
			contractValue: "factory-status-v1",
			requiredFields: []string{
				"sequence", "runId", "eventType", "timestamp", "message", "summary", "metadata",
			},
			requiredValues: []string{
				factory.EventTypeRunCreated,
				factory.EventTypeStepStarted,
				factory.EventTypeStepEnded,
				factory.EventTypeCommandOutputSummary,
				factory.EventTypeVerificationResult,
				factory.EventTypeCIState,
				factory.EventTypeArtifactSync,
				factory.EventTypeFailureClassification,
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

func TestFactoryContractExamplesMatchCommandSchemas(t *testing.T) {
	t.Run("factory list example", func(t *testing.T) {
		var resp FactoryListResponse
		raw := decodeStrictJSONExample(t, "../docs/contracts/examples/factory-list-v1.json", &resp)

		requireExactKeys(t, raw, []string{"contractVersion", "runs"})
		if resp.ContractVersion != FactoryListContractVersion {
			t.Fatalf("contractVersion = %q, want %q", resp.ContractVersion, FactoryListContractVersion)
		}
		if len(resp.Runs) == 0 {
			t.Fatal("factory list example should include at least one run")
		}
	})

	t.Run("factory status example", func(t *testing.T) {
		var resp FactoryStatusResponse
		raw := decodeStrictJSONExample(t, "../docs/contracts/examples/factory-status-v1.json", &resp)

		requireExactKeys(t, raw, []string{"contractVersion", "run", "timeline"})
		if resp.ContractVersion != FactoryStatusContractVersion {
			t.Fatalf("contractVersion = %q, want %q", resp.ContractVersion, FactoryStatusContractVersion)
		}
		if resp.Run.RunID == "" {
			t.Fatal("factory status example should include a run ID")
		}
		if len(resp.Timeline) == 0 {
			t.Fatal("factory status example should include timeline events")
		}
		if resp.Run.Verification == nil {
			t.Fatal("factory status example should include verification metadata")
		}
		if resp.Run.Verification.Summary.Total == 0 {
			t.Fatal("factory status example should include verification summary totals")
		}
		if len(resp.Run.Verification.Artifacts) == 0 {
			t.Fatal("factory status example should include verification artifact references")
		}
	})

	t.Run("factory run example", func(t *testing.T) {
		var resp FactoryRunResponse
		raw := decodeStrictJSONExample(t, "../docs/contracts/examples/factory-run-v1.json", &resp)

		requireExactKeys(t, raw, []string{"contractVersion", "version", "runId", "status", "nextAction", "artifacts", "eventSummary", "failure"})
		if resp.ContractVersion != FactoryRunContractVersion {
			t.Fatalf("contractVersion = %q, want %q", resp.ContractVersion, FactoryRunContractVersion)
		}
		if resp.RunID == "" {
			t.Fatal("factory run example should include a run ID")
		}
		if resp.NextAction == nil {
			t.Fatal("factory run example should include nextAction")
		}
		if len(resp.Artifacts) == 0 {
			t.Fatal("factory run example should include artifacts")
		}
		if resp.EventSummary.Total == 0 {
			t.Fatal("factory run example should include event summary totals")
		}
		if resp.Failure == nil {
			t.Fatal("factory run example should include failure details")
		}
	})
}

func TestVerifyContractExamplesMatchSchema(t *testing.T) {
	topLevelKeys := []string{"schemaVersion", "generatedAt", "status", "summary", "checks", "warnings", "artifacts"}
	summaryKeys := []string{"total", "passed", "failed", "timedOut", "missing", "skipped", "warnings"}
	checkKeys := []string{
		"id",
		"name",
		"adapter",
		"status",
		"required",
		"command",
		"workDir",
		"timeoutSeconds",
		"startedAt",
		"finishedAt",
		"durationMs",
		"exitCode",
		"stdoutArtifact",
		"stderrArtifact",
		"message",
	}
	warningKeys := []string{"checkId", "status", "message"}
	artifactKeys := []string{"checkId", "kind", "path"}

	tests := []struct {
		name       string
		path       string
		wantStatus string
	}{
		{name: "pass example", path: "../docs/contracts/examples/verify-v1-pass.json", wantStatus: verify.StatusPass},
		{name: "fail example", path: "../docs/contracts/examples/verify-v1-fail.json", wantStatus: verify.StatusFail},
		{name: "warn example", path: "../docs/contracts/examples/verify-v1-warn.json", wantStatus: verify.StatusWarn},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result verify.Result
			raw := decodeStrictJSONExample(t, tt.path, &result)

			requireExactKeys(t, raw, topLevelKeys)
			if result.SchemaVersion != verify.SchemaVersion {
				t.Fatalf("schemaVersion = %q, want %q", result.SchemaVersion, verify.SchemaVersion)
			}
			if result.Status != tt.wantStatus {
				t.Fatalf("status = %q, want %q", result.Status, tt.wantStatus)
			}
			if len(result.Checks) == 0 {
				t.Fatal("example should include at least one check")
			}

			summary, ok := raw["summary"].(map[string]interface{})
			if !ok {
				t.Fatalf("summary should be an object, got %T", raw["summary"])
			}
			requireExactKeys(t, summary, summaryKeys)

			checks, ok := raw["checks"].([]interface{})
			if !ok {
				t.Fatalf("checks should be an array, got %T", raw["checks"])
			}
			for i, item := range checks {
				check, ok := item.(map[string]interface{})
				if !ok {
					t.Fatalf("checks[%d] should be an object, got %T", i, item)
				}
				requireExactKeys(t, check, checkKeys)
			}

			warnings, ok := raw["warnings"].([]interface{})
			if !ok {
				t.Fatalf("warnings should be an array, got %T", raw["warnings"])
			}
			for i, item := range warnings {
				warning, ok := item.(map[string]interface{})
				if !ok {
					t.Fatalf("warnings[%d] should be an object, got %T", i, item)
				}
				requireExactKeys(t, warning, warningKeys)
			}

			artifacts, ok := raw["artifacts"].([]interface{})
			if !ok {
				t.Fatalf("artifacts should be an array, got %T", raw["artifacts"])
			}
			for i, item := range artifacts {
				artifact, ok := item.(map[string]interface{})
				if !ok {
					t.Fatalf("artifacts[%d] should be an object, got %T", i, item)
				}
				requireExactKeys(t, artifact, artifactKeys)
			}
		})
	}
}

func decodeStrictJSONExample(t *testing.T, path string, out any) map[string]interface{} {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		t.Fatalf("decode %s against command schema: %v", path, err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parse %s as JSON object: %v", path, err)
	}
	return raw
}
