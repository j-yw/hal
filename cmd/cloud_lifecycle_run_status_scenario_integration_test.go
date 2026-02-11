//go:build integration
// +build integration

package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/cloud"
)

// Legacy snake_case aliases still emitted by some cloud command JSON responses.
// Keep this mapping centralized so lifecycle scenarios can assert canonical
// camelCase contract keys while remaining compatible during migration.
var cloudLifecycleJSONLegacyAliases = map[string]string{
	cloudLifecycleJSONKeyRunID:                "run_id",
	cloudLifecycleJSONKeyWorkflowKind:         "workflow_kind",
	cloudLifecycleJSONKeyAttemptCount:         "attempt_count",
	cloudLifecycleJSONKeyMaxAttempts:          "max_attempts",
	cloudLifecycleJSONKeyCurrentAttempt:       "current_attempt",
	cloudLifecycleJSONKeyLastHeartbeatAgeSecs: "last_heartbeat_age_seconds",
	cloudLifecycleJSONKeyDeadlineAt:           "deadline_at",
	cloudLifecycleJSONKeyAuthProfileID:        "auth_profile_id",
	cloudLifecycleJSONKeyCreatedAt:            "created_at",
	cloudLifecycleJSONKeyUpdatedAt:            "updated_at",
	cloudLifecycleJSONKeyCancelRequested:      "cancel_requested",
	cloudLifecycleJSONKeyTerminalStatus:       "terminal_status",
	cloudLifecycleJSONKeyCanceledAt:           "canceled_at",
	cloudLifecycleJSONKeySnapshotVersion:      "snapshot_version",
	cloudLifecycleJSONKeyFilesRestored:        "files_restored",
	cloudLifecycleJSONKeyErrorCode:            "error_code",
}

func TestCloudLifecycleScenario_SetupRunStatus(t *testing.T) {
	h := setupCloudLifecycleIntegrationHarness(t)
	runner := newCloudLifecycleCommandRunner(h)

	setupFixture := mustLifecycleCheckpointFixture(t, cloudLifecycleCheckpointSetup)
	runFixture := mustLifecycleCheckpointFixture(t, cloudLifecycleCheckpointRun)
	statusFixture := mustLifecycleCheckpointFixture(t, cloudLifecycleCheckpointStatus)

	setupResult := runner.Run(cloudLifecycleCommandInvocation{
		Args: lifecycleCommandArgs(t, setupFixture.CommandName),
	})
	if setupResult.Err != nil {
		t.Fatalf("cloud setup failed: %v\noutput:\n%s", setupResult.Err, setupResult.Output)
	}
	assertLifecycleOutputContains(t, setupResult.Output, "Cloud profile configured.")

	runHuman := runner.Run(cloudLifecycleCommandInvocation{
		Args: lifecycleCommandArgs(t, runFixture.CommandName),
	})
	if runHuman.Err != nil {
		t.Fatalf("run --cloud (human) failed: %v\noutput:\n%s", runHuman.Err, runHuman.Output)
	}
	assertLifecycleOutputContains(t, runHuman.Output,
		"Run submitted.",
		"run_id:",
		"status:",
		"Next: hal cloud status",
	)

	humanRunID := mustLifecycleRunIDFromHumanOutput(t, runHuman.Output)
	assertLifecycleRunPersisted(t, h, humanRunID, cloud.WorkflowKindRun)

	statusHuman := runner.Run(cloudLifecycleCommandInvocation{
		Args:  lifecycleCommandArgs(t, statusFixture.CommandName),
		RunID: humanRunID,
	})
	if statusHuman.Err != nil {
		t.Fatalf("cloud status (human) failed: %v\noutput:\n%s", statusHuman.Err, statusHuman.Output)
	}
	assertLifecycleOutputContains(t, statusHuman.Output,
		"Run status:",
		"run_id:",
		humanRunID,
		"workflow_kind:",
		string(cloud.WorkflowKindRun),
	)

	runJSON := runner.Run(cloudLifecycleCommandInvocation{
		Args: lifecycleCommandArgs(t, runFixture.CommandName),
		JSON: true,
	})
	if runJSON.Err != nil {
		t.Fatalf("run --cloud --json failed: %v\noutput:\n%s", runJSON.Err, runJSON.Output)
	}

	runPayload := mustDecodeLifecycleJSONOutput(t, runJSON.Output)
	assertLifecycleRequiredJSONKeys(t, runPayload, runFixture.RequiredJSONKeys)
	jsonRunID := mustLifecycleJSONStringField(t, runPayload, cloudLifecycleJSONKeyRunID)
	if got := mustLifecycleJSONStringField(t, runPayload, cloudLifecycleJSONKeyWorkflowKind); got != string(cloud.WorkflowKindRun) {
		t.Fatalf("run workflowKind = %q, want %q", got, cloud.WorkflowKindRun)
	}
	assertLifecycleRunPersisted(t, h, jsonRunID, cloud.WorkflowKindRun)

	statusJSON := runner.Run(cloudLifecycleCommandInvocation{
		Args:  lifecycleCommandArgs(t, statusFixture.CommandName),
		RunID: jsonRunID,
		JSON:  true,
	})
	if statusJSON.Err != nil {
		t.Fatalf("cloud status --json failed: %v\noutput:\n%s", statusJSON.Err, statusJSON.Output)
	}

	statusPayload := mustDecodeLifecycleJSONOutput(t, statusJSON.Output)
	assertLifecycleRequiredJSONKeys(t, statusPayload, statusFixture.RequiredJSONKeys)
	if got := mustLifecycleJSONStringField(t, statusPayload, cloudLifecycleJSONKeyRunID); got != jsonRunID {
		t.Fatalf("status run ID = %q, want %q", got, jsonRunID)
	}
	if got := mustLifecycleJSONStringField(t, statusPayload, cloudLifecycleJSONKeyWorkflowKind); got != string(cloud.WorkflowKindRun) {
		t.Fatalf("status workflowKind = %q, want %q", got, cloud.WorkflowKindRun)
	}
}

func mustLifecycleCheckpointFixture(t *testing.T, checkpoint cloudLifecycleCheckpoint) cloudLifecycleCheckpointFixture {
	t.Helper()
	fixture, ok := cloudLifecycleCheckpointFixtures[checkpoint]
	if !ok {
		t.Fatalf("missing lifecycle checkpoint fixture %q", checkpoint)
	}
	return fixture
}

func mustLifecycleRunIDFromHumanOutput(t *testing.T, output string) string {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "run_id:") {
			continue
		}
		runID := strings.TrimSpace(strings.TrimPrefix(line, "run_id:"))
		if runID != "" {
			return runID
		}
	}
	t.Fatalf("run_id not found in output:\n%s", output)
	return ""
}

func assertLifecycleRunPersisted(t *testing.T, h *cloudLifecycleIntegrationHarness, runID string, kind cloud.WorkflowKind) {
	t.Helper()
	run, err := h.Store.GetRun(context.Background(), runID)
	if err != nil {
		t.Fatalf("persisted run %q not found in harness store: %v", runID, err)
	}
	if run.WorkflowKind != kind {
		t.Fatalf("persisted run %q workflow kind = %q, want %q", runID, run.WorkflowKind, kind)
	}
}

func assertLifecycleOutputContains(t *testing.T, output string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q\noutput:\n%s", want, output)
		}
	}
}

func assertLifecycleRequiredJSONKeys(t *testing.T, payload map[string]interface{}, required []string) {
	t.Helper()
	for _, key := range required {
		candidates := lifecycleJSONKeyCandidates(key)
		if _, ok := lifecycleJSONFirstKey(payload, candidates...); !ok {
			t.Fatalf("JSON payload missing required key %q (checked aliases %v): %v", key, candidates, payload)
		}
	}
}

func mustLifecycleJSONStringField(t *testing.T, payload map[string]interface{}, key string) string {
	t.Helper()
	candidates := lifecycleJSONKeyCandidates(key)
	value, ok := lifecycleJSONStringField(payload, candidates...)
	if !ok {
		t.Fatalf("JSON payload missing string field %q (checked aliases %v): %v", key, candidates, payload)
	}
	return value
}

func lifecycleJSONKeyCandidates(canonical string) []string {
	if alias, ok := cloudLifecycleJSONLegacyAliases[canonical]; ok && alias != "" {
		return []string{canonical, alias}
	}
	return []string{canonical}
}
