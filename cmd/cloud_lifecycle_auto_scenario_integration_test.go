//go:build integration
// +build integration

package cmd

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
)

func TestCloudLifecycleScenario_AutoStatusLogs(t *testing.T) {
	h := setupCloudLifecycleIntegrationHarness(t)
	runner := newCloudLifecycleCommandRunner(h)

	setupFixture := mustLifecycleCheckpointFixture(t, cloudLifecycleCheckpointSetup)
	statusFixture := mustLifecycleCheckpointFixture(t, cloudLifecycleCheckpointStatus)
	logsFixture := mustLifecycleCheckpointFixture(t, cloudLifecycleCheckpointLogs)
	autoWorkflowFixture := mustLifecycleWorkflowFixtureForCommand(t, "auto")

	setupResult := runner.Run(cloudLifecycleCommandInvocation{
		Args: lifecycleCommandArgs(t, setupFixture.CommandName),
	})
	if setupResult.Err != nil {
		t.Fatalf("cloud setup failed: %v\noutput:\n%s", setupResult.Err, setupResult.Output)
	}
	assertLifecycleOutputContains(t, setupResult.Output, "Cloud profile configured.")

	autoJSON := runner.Run(cloudLifecycleCommandInvocation{
		Args: lifecycleCommandArgs(t, autoWorkflowFixture.CommandName),
		JSON: true,
	})
	if autoJSON.Err != nil {
		t.Fatalf("auto --cloud --json failed: %v\noutput:\n%s", autoJSON.Err, autoJSON.Output)
	}

	autoPayload := mustDecodeLifecycleJSONOutput(t, autoJSON.Output)
	assertLifecycleRequiredJSONKeys(t, autoPayload, autoWorkflowFixture.RequiredJSONKeys)
	autoRunID := mustLifecycleJSONStringField(t, autoPayload, cloudLifecycleJSONKeyRunID)
	if got := mustLifecycleJSONStringField(t, autoPayload, cloudLifecycleJSONKeyWorkflowKind); got != string(cloud.WorkflowKindAuto) {
		t.Fatalf("auto workflowKind = %q, want %q", got, cloud.WorkflowKindAuto)
	}
	assertLifecycleRunPersisted(t, h, autoRunID, cloud.WorkflowKindAuto)

	statusHuman := runner.Run(cloudLifecycleCommandInvocation{
		Args:  lifecycleCommandArgs(t, statusFixture.CommandName),
		RunID: autoRunID,
	})
	if statusHuman.Err != nil {
		t.Fatalf("cloud status failed: %v\noutput:\n%s", statusHuman.Err, statusHuman.Output)
	}
	assertLifecycleOutputContains(t, statusHuman.Output,
		"Run status:",
		"run_id:",
		autoRunID,
		"workflow_kind:",
		string(cloud.WorkflowKindAuto),
	)

	statusJSON := runner.Run(cloudLifecycleCommandInvocation{
		Args:  lifecycleCommandArgs(t, statusFixture.CommandName),
		RunID: autoRunID,
		JSON:  true,
	})
	if statusJSON.Err != nil {
		t.Fatalf("cloud status --json failed: %v\noutput:\n%s", statusJSON.Err, statusJSON.Output)
	}

	statusPayload := mustDecodeLifecycleJSONOutput(t, statusJSON.Output)
	assertLifecycleRequiredJSONKeys(t, statusPayload, statusFixture.RequiredJSONKeys)
	if got := mustLifecycleJSONStringField(t, statusPayload, cloudLifecycleJSONKeyRunID); got != autoRunID {
		t.Fatalf("status run ID = %q, want %q", got, autoRunID)
	}
	if got := mustLifecycleJSONStringField(t, statusPayload, cloudLifecycleJSONKeyWorkflowKind); got != string(cloud.WorkflowKindAuto) {
		t.Fatalf("status workflowKind = %q, want %q", got, cloud.WorkflowKindAuto)
	}

	eventPayload := fmt.Sprintf(`{"runId":"%s","workflowKind":"%s","message":"auto lifecycle log"}`,
		autoRunID,
		cloud.WorkflowKindAuto,
	)
	if err := h.Store.InsertEvent(context.Background(), &cloud.Event{
		ID:          autoRunID + "-auto-log-1",
		RunID:       autoRunID,
		EventType:   "auto_checkpoint",
		PayloadJSON: &eventPayload,
		CreatedAt:   time.Date(2026, 2, 12, 2, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("failed to seed auto lifecycle log event: %v", err)
	}

	logsJSON := runner.Run(cloudLifecycleCommandInvocation{
		Args:  lifecycleCommandArgs(t, logsFixture.CommandName),
		RunID: autoRunID,
		JSON:  true,
	})
	if logsJSON.Err != nil {
		t.Fatalf("cloud logs --json failed: %v\noutput:\n%s", logsJSON.Err, logsJSON.Output)
	}

	logsPayload := mustDecodeLifecycleJSONOutput(t, logsJSON.Output)
	assertLifecycleRequiredJSONKeys(t, logsPayload, logsFixture.RequiredJSONKeys)
	if got := mustLifecycleJSONStringField(t, logsPayload, cloudLifecycleJSONKeyRunID); got != autoRunID {
		t.Fatalf("logs run ID = %q, want %q", got, autoRunID)
	}

	eventsRaw, ok := logsPayload[cloudLifecycleJSONKeyEvents]
	if !ok {
		t.Fatalf("logs JSON missing events field: %v", logsPayload)
	}
	events, ok := eventsRaw.([]interface{})
	if !ok {
		t.Fatalf("logs events type = %T, want []interface{}", eventsRaw)
	}
	if len(events) != 1 {
		t.Fatalf("logs events count = %d, want 1", len(events))
	}

	firstEvent, ok := events[0].(map[string]interface{})
	if !ok {
		t.Fatalf("logs first event type = %T, want map[string]interface{}", events[0])
	}
	eventType, ok := lifecycleJSONStringField(firstEvent, "eventType", "event_type")
	if !ok || eventType != "auto_checkpoint" {
		t.Fatalf("logs event type = %q, want %q", eventType, "auto_checkpoint")
	}
	payloadText, ok := lifecycleJSONStringField(firstEvent, "payloadJson", "payload_json")
	if !ok {
		t.Fatalf("logs first event missing payload JSON: %v", firstEvent)
	}
	if !strings.Contains(payloadText, string(cloud.WorkflowKindAuto)) {
		t.Fatalf("logs payload should include workflowKind %q: %s", cloud.WorkflowKindAuto, payloadText)
	}
}
