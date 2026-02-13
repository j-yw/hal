//go:build integration
// +build integration

package cmd

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
)

func TestCloudLifecycleScenario_ReviewStatusLogs(t *testing.T) {
	h := setupCloudLifecycleIntegrationHarness(t)
	runner := newCloudLifecycleCommandRunner(h)

	setupFixture := mustLifecycleCheckpointFixture(t, cloudLifecycleCheckpointSetup)
	statusFixture := mustLifecycleCheckpointFixture(t, cloudLifecycleCheckpointStatus)
	logsFixture := mustLifecycleCheckpointFixture(t, cloudLifecycleCheckpointLogs)
	reviewWorkflowFixture := mustLifecycleWorkflowFixtureForCommand(t, "review")

	setupResult := runner.Run(cloudLifecycleCommandInvocation{
		Args: lifecycleCommandArgs(t, setupFixture.CommandName),
	})
	if setupResult.Err != nil {
		t.Fatalf("cloud setup failed: %v\noutput:\n%s", setupResult.Err, setupResult.Output)
	}
	assertLifecycleOutputContains(t, setupResult.Output, "Cloud profile configured.")

	reviewJSON := runner.Run(cloudLifecycleCommandInvocation{
		Args: lifecycleCommandArgs(t, reviewWorkflowFixture.CommandName),
		JSON: true,
	})
	if reviewJSON.Err != nil {
		t.Fatalf("review --cloud --json failed: %v\noutput:\n%s", reviewJSON.Err, reviewJSON.Output)
	}

	reviewPayload := mustDecodeLifecycleJSONOutput(t, reviewJSON.Output)
	assertLifecycleRequiredJSONKeys(t, reviewPayload, reviewWorkflowFixture.RequiredJSONKeys)
	reviewRunID := mustLifecycleJSONStringField(t, reviewPayload, cloudLifecycleJSONKeyRunID)
	if got := mustLifecycleJSONStringField(t, reviewPayload, cloudLifecycleJSONKeyWorkflowKind); got != string(cloud.WorkflowKindReview) {
		t.Fatalf("review workflowKind = %q, want %q", got, cloud.WorkflowKindReview)
	}
	assertLifecycleRunPersisted(t, h, reviewRunID, cloud.WorkflowKindReview)

	statusHuman := runner.Run(cloudLifecycleCommandInvocation{
		Args:  lifecycleCommandArgs(t, statusFixture.CommandName),
		RunID: reviewRunID,
	})
	if statusHuman.Err != nil {
		t.Fatalf("cloud status failed: %v\noutput:\n%s", statusHuman.Err, statusHuman.Output)
	}
	assertLifecycleOutputContains(t, statusHuman.Output,
		"Run status:",
		"run_id:",
		reviewRunID,
		"workflow_kind:",
		string(cloud.WorkflowKindReview),
	)

	statusJSON := runner.Run(cloudLifecycleCommandInvocation{
		Args:  lifecycleCommandArgs(t, statusFixture.CommandName),
		RunID: reviewRunID,
		JSON:  true,
	})
	if statusJSON.Err != nil {
		t.Fatalf("cloud status --json failed: %v\noutput:\n%s", statusJSON.Err, statusJSON.Output)
	}

	statusPayload := mustDecodeLifecycleJSONOutput(t, statusJSON.Output)
	assertLifecycleRequiredJSONKeys(t, statusPayload, statusFixture.RequiredJSONKeys)
	if got := mustLifecycleJSONStringField(t, statusPayload, cloudLifecycleJSONKeyRunID); got != reviewRunID {
		t.Fatalf("status run ID = %q, want %q", got, reviewRunID)
	}
	if got := mustLifecycleJSONStringField(t, statusPayload, cloudLifecycleJSONKeyWorkflowKind); got != string(cloud.WorkflowKindReview) {
		t.Fatalf("status workflowKind = %q, want %q", got, cloud.WorkflowKindReview)
	}

	eventPayload := fmt.Sprintf(`{"runId":"%s","workflowKind":"%s","message":"review lifecycle log"}`,
		reviewRunID,
		cloud.WorkflowKindReview,
	)
	h.SeedTimelineEvents(t, reviewRunID, cloudLifecycleTimelineEventSeed{
		ID:          reviewRunID + "-review-log-1",
		EventType:   "review_checkpoint",
		PayloadJSON: &eventPayload,
		CreatedAt:   time.Date(2026, 2, 12, 2, 30, 0, 0, time.UTC),
	})

	logsJSON := runner.Run(cloudLifecycleCommandInvocation{
		Args:  lifecycleCommandArgs(t, logsFixture.CommandName),
		RunID: reviewRunID,
		JSON:  true,
	})
	if logsJSON.Err != nil {
		t.Fatalf("cloud logs --json failed: %v\noutput:\n%s", logsJSON.Err, logsJSON.Output)
	}

	logsPayload := mustDecodeLifecycleJSONOutput(t, logsJSON.Output)
	assertLifecycleRequiredJSONKeys(t, logsPayload, logsFixture.RequiredJSONKeys)
	if got := mustLifecycleJSONStringField(t, logsPayload, cloudLifecycleJSONKeyRunID); got != reviewRunID {
		t.Fatalf("logs run ID = %q, want %q", got, reviewRunID)
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
	if !ok || eventType != "review_checkpoint" {
		t.Fatalf("logs event type = %q, want %q", eventType, "review_checkpoint")
	}
	payloadText, ok := lifecycleJSONStringField(firstEvent, "payloadJson", "payload_json")
	if !ok {
		t.Fatalf("logs first event missing payload JSON: %v", firstEvent)
	}
	if !strings.Contains(payloadText, string(cloud.WorkflowKindReview)) {
		t.Fatalf("logs payload should include workflowKind %q: %s", cloud.WorkflowKindReview, payloadText)
	}
}
