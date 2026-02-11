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

func TestCloudLifecycleScenario_RunLogs(t *testing.T) {
	h := setupCloudLifecycleIntegrationHarness(t)
	runner := newCloudLifecycleCommandRunner(h)

	setupFixture := mustLifecycleCheckpointFixture(t, cloudLifecycleCheckpointSetup)
	runFixture := mustLifecycleCheckpointFixture(t, cloudLifecycleCheckpointRun)
	logsFixture := mustLifecycleCheckpointFixture(t, cloudLifecycleCheckpointLogs)

	setupResult := runner.Run(cloudLifecycleCommandInvocation{
		Args: lifecycleCommandArgs(t, setupFixture.CommandName),
	})
	if setupResult.Err != nil {
		t.Fatalf("cloud setup failed: %v\noutput:\n%s", setupResult.Err, setupResult.Output)
	}
	assertLifecycleOutputContains(t, setupResult.Output, "Cloud profile configured.")

	runResult := runner.Run(cloudLifecycleCommandInvocation{
		Args: lifecycleCommandArgs(t, runFixture.CommandName),
	})
	if runResult.Err != nil {
		t.Fatalf("run --cloud failed: %v\noutput:\n%s", runResult.Err, runResult.Output)
	}
	assertLifecycleOutputContains(t, runResult.Output,
		"Run submitted.",
		"run_id:",
		"status:",
	)

	runID := mustLifecycleRunIDFromHumanOutput(t, runResult.Output)
	assertLifecycleRunPersisted(t, h, runID, cloud.WorkflowKindRun)

	seededAt := time.Date(2026, 2, 12, 0, 0, 0, 0, time.UTC)
	firstPayload := fmt.Sprintf(`{"runId":"%s","message":"sandbox ready"}`, runID)
	secondPayload := fmt.Sprintf(`{"runId":"%s","message":"execution finished"}`, runID)

	for i, event := range []struct {
		eventType string
		payload   *string
	}{
		{eventType: "sandbox_ready", payload: &firstPayload},
		{eventType: "execution_finished", payload: &secondPayload},
	} {
		err := h.Store.InsertEvent(context.Background(), &cloud.Event{
			ID:          fmt.Sprintf("%s-log-%d", runID, i+1),
			RunID:       runID,
			EventType:   event.eventType,
			PayloadJSON: event.payload,
			CreatedAt:   seededAt.Add(time.Duration(i) * time.Second),
		})
		if err != nil {
			t.Fatalf("failed to seed lifecycle log event %d: %v", i+1, err)
		}
	}

	logsHuman := runner.Run(cloudLifecycleCommandInvocation{
		Args:  lifecycleCommandArgs(t, logsFixture.CommandName),
		RunID: runID,
	})
	if logsHuman.Err != nil {
		t.Fatalf("cloud logs (human) failed: %v\noutput:\n%s", logsHuman.Err, logsHuman.Output)
	}
	assertLifecycleOutputContains(t, logsHuman.Output,
		"sandbox_ready",
		"execution_finished",
		runID,
	)

	logsJSON := runner.Run(cloudLifecycleCommandInvocation{
		Args:  lifecycleCommandArgs(t, logsFixture.CommandName),
		RunID: runID,
		JSON:  true,
	})
	if logsJSON.Err != nil {
		t.Fatalf("cloud logs --json failed: %v\noutput:\n%s", logsJSON.Err, logsJSON.Output)
	}

	logsPayload := mustDecodeLifecycleJSONOutput(t, logsJSON.Output)
	assertLifecycleRequiredJSONKeys(t, logsPayload, logsFixture.RequiredJSONKeys)
	if got := mustLifecycleJSONStringField(t, logsPayload, cloudLifecycleJSONKeyRunID); got != runID {
		t.Fatalf("logs run ID = %q, want %q", got, runID)
	}

	eventsRaw, ok := logsPayload[cloudLifecycleJSONKeyEvents]
	if !ok {
		t.Fatalf("logs JSON missing events payload: %v", logsPayload)
	}
	events, ok := eventsRaw.([]interface{})
	if !ok {
		t.Fatalf("logs events type = %T, want []interface{}", eventsRaw)
	}
	if len(events) != 2 {
		t.Fatalf("logs events count = %d, want 2", len(events))
	}

	firstEvent, ok := events[0].(map[string]interface{})
	if !ok {
		t.Fatalf("logs first event type = %T, want map[string]interface{}", events[0])
	}
	if _, ok := lifecycleJSONStringField(firstEvent, "id"); !ok {
		t.Fatalf("logs first event missing id: %v", firstEvent)
	}
	if eventType, ok := lifecycleJSONStringField(firstEvent, "eventType", "event_type"); !ok || eventType != "sandbox_ready" {
		t.Fatalf("logs first event type = %q, want %q", eventType, "sandbox_ready")
	}
	payloadValue, ok := lifecycleJSONStringField(firstEvent, "payloadJson", "payload_json")
	if !ok {
		t.Fatalf("logs first event missing payload JSON: %v", firstEvent)
	}
	if !strings.Contains(payloadValue, runID) {
		t.Fatalf("logs first event payload should reference run ID %q: %s", runID, payloadValue)
	}
	if _, ok := lifecycleJSONStringField(firstEvent, "createdAt", "created_at"); !ok {
		t.Fatalf("logs first event missing createdAt: %v", firstEvent)
	}
}
