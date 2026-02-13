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

func TestWorkerLifecycleSuccessScenarios(t *testing.T) {
	for _, workflow := range workerLifecycleWorkflowFixtures {
		workflow := workflow
		runWorkerLifecycleAdapterMatrix(t, "success_"+workflow.Name, func(t *testing.T, scenario workerLifecycleAdapterScenario) {
			flow := workerLifecycleFlowForWorkflow(workflow.WorkflowCommand)
			if len(flow) < 3 {
				t.Fatalf("workflow flow must include setup/submit/status steps, got %d steps", len(flow))
			}

			setupResult := scenario.Runner.Run(workerLifecycleFlowRunInput{Step: flow[0]})
			if setupResult.Err != nil {
				t.Fatalf("setup step failed: %v\noutput:\n%s", setupResult.Err, setupResult.Output)
			}
			if !strings.Contains(setupResult.Output, "Cloud profile configured.") {
				t.Fatalf("setup output missing success message:\n%s", setupResult.Output)
			}

			submitResult := scenario.Runner.Run(workerLifecycleFlowRunInput{Step: flow[1], JSON: true})
			if submitResult.Err != nil {
				t.Fatalf("submit step failed: %v\noutput:\n%s", submitResult.Err, submitResult.Output)
			}

			submitPayload := mustDecodeLifecycleJSONOutput(t, submitResult.Output)
			runID := mustLifecycleJSONStringField(t, submitPayload, cloudLifecycleJSONKeyRunID)
			if got := mustLifecycleJSONStringField(t, submitPayload, cloudLifecycleJSONKeyWorkflowKind); got != string(workflow.WorkflowKind) {
				t.Fatalf("submit workflowKind = %q, want %q", got, workflow.WorkflowKind)
			}

			seedWorkerLifecycleSuccessState(t, scenario.Harness, runID)

			statusResult := scenario.Runner.Run(workerLifecycleFlowRunInput{Step: flow[2], RunID: runID, JSON: true})
			if statusResult.Err != nil {
				t.Fatalf("status step failed: %v\noutput:\n%s", statusResult.Err, statusResult.Output)
			}

			statusPayload := mustDecodeLifecycleJSONOutput(t, statusResult.Output)
			if got := mustLifecycleJSONStringField(t, statusPayload, cloudLifecycleJSONKeyRunID); got != runID {
				t.Fatalf("status runID = %q, want %q", got, runID)
			}
			if got := mustLifecycleJSONStringField(t, statusPayload, cloudLifecycleJSONKeyWorkflowKind); got != string(workflow.WorkflowKind) {
				t.Fatalf("status workflowKind = %q, want %q", got, workflow.WorkflowKind)
			}
			if got := mustLifecycleJSONStringField(t, statusPayload, cloudLifecycleJSONKeyStatus); got != string(cloud.RunStatusSucceeded) {
				t.Fatalf("status = %q, want %q", got, cloud.RunStatusSucceeded)
			}

			assertWorkerLifecycleTerminalSuccess(t, scenario.Harness, runID)
			assertWorkerLifecycleSnapshotRefsPresent(t, scenario.Harness, runID)
		})
	}
}

func seedWorkerLifecycleSuccessState(t *testing.T, h *cloudLifecycleIntegrationHarness, runID string) {
	t.Helper()

	ctx := context.Background()
	run, err := h.Store.GetRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetRun(%q): %v", runID, err)
	}

	run.AttemptCount = 1

	if err := h.Store.TransitionRun(ctx, runID, run.Status, cloud.RunStatusClaimed); err != nil {
		t.Fatalf("TransitionRun(%q queued->claimed): %v", runID, err)
	}

	startedAt := time.Now().UTC().Truncate(time.Second)
	attemptID := fmt.Sprintf("%s-attempt-1", runID)
	attempt := &cloud.Attempt{
		ID:             attemptID,
		RunID:          runID,
		AttemptNumber:  1,
		WorkerID:       "worker-success",
		Status:         cloud.AttemptStatusActive,
		StartedAt:      startedAt,
		HeartbeatAt:    startedAt,
		LeaseExpiresAt: startedAt.Add(30 * time.Second),
	}
	if err := h.Store.CreateAttempt(ctx, attempt); err != nil {
		t.Fatalf("CreateAttempt(%q): %v", runID, err)
	}

	if err := h.Store.TransitionRun(ctx, runID, cloud.RunStatusClaimed, cloud.RunStatusRunning); err != nil {
		t.Fatalf("TransitionRun(%q claimed->running): %v", runID, err)
	}

	endedAt := startedAt.Add(2 * time.Second)
	if err := h.Store.TransitionAttempt(ctx, attemptID, cloud.AttemptStatusSucceeded, endedAt, nil, nil); err != nil {
		t.Fatalf("TransitionAttempt(%q -> succeeded): %v", attemptID, err)
	}

	if err := h.Store.TransitionRun(ctx, runID, cloud.RunStatusRunning, cloud.RunStatusSucceeded); err != nil {
		t.Fatalf("TransitionRun(%q running->succeeded): %v", runID, err)
	}

	inputSnapshotID := run.InputSnapshotID
	if inputSnapshotID == nil || strings.TrimSpace(*inputSnapshotID) == "" {
		fallbackInput := fmt.Sprintf("%s-input-snapshot", runID)
		inputSnapshotID = &fallbackInput
	}
	latestSnapshotID := fmt.Sprintf("%s-latest-snapshot", runID)
	latestVersion := run.LatestSnapshotVersion + 1
	if latestVersion < 2 {
		latestVersion = 2
	}
	if err := h.Store.UpdateRunSnapshotRefs(ctx, runID, inputSnapshotID, &latestSnapshotID, latestVersion); err != nil {
		t.Fatalf("UpdateRunSnapshotRefs(%q): %v", runID, err)
	}
}

func assertWorkerLifecycleTerminalSuccess(t *testing.T, h *cloudLifecycleIntegrationHarness, runID string) {
	t.Helper()

	run, err := h.Store.GetRun(context.Background(), runID)
	if err != nil {
		t.Fatalf("GetRun(%q): %v", runID, err)
	}
	if run.Status != cloud.RunStatusSucceeded {
		t.Fatalf("persisted run status = %q, want %q", run.Status, cloud.RunStatusSucceeded)
	}
	if !run.Status.IsTerminal() {
		t.Fatalf("persisted run status %q must be terminal", run.Status)
	}

	transitions := h.Store.RunTransitions(runID)
	if len(transitions) == 0 {
		t.Fatalf("run %q has no recorded transitions", runID)
	}
	lastTransition := transitions[len(transitions)-1]
	if lastTransition.To != cloud.RunStatusSucceeded {
		t.Fatalf("last run transition = %q -> %q, want terminal to %q", lastTransition.From, lastTransition.To, cloud.RunStatusSucceeded)
	}

	terminalizations := h.Store.AttemptTerminalizations(runID)
	if len(terminalizations) == 0 {
		t.Fatalf("run %q has no attempt terminalization records", runID)
	}
	finalAttempt := terminalizations[len(terminalizations)-1]
	if finalAttempt.Status != cloud.AttemptStatusSucceeded {
		t.Fatalf("final attempt status = %q, want %q", finalAttempt.Status, cloud.AttemptStatusSucceeded)
	}
	if !finalAttempt.Status.IsTerminal() {
		t.Fatalf("final attempt status %q must be terminal", finalAttempt.Status)
	}
}

func assertWorkerLifecycleSnapshotRefsPresent(t *testing.T, h *cloudLifecycleIntegrationHarness, runID string) {
	t.Helper()

	refs, ok := h.Store.SnapshotRefs(runID)
	if !ok {
		t.Fatalf("SnapshotRefs(%q) not found", runID)
	}
	if refs.InputSnapshotID == nil || strings.TrimSpace(*refs.InputSnapshotID) == "" {
		t.Fatalf("InputSnapshotID must be present for run %q: %#v", runID, refs)
	}
	if refs.LatestSnapshotID == nil || strings.TrimSpace(*refs.LatestSnapshotID) == "" {
		t.Fatalf("LatestSnapshotID must be present for run %q: %#v", runID, refs)
	}
	if refs.LatestSnapshotVersion <= 0 {
		t.Fatalf("LatestSnapshotVersion must be > 0 for run %q, got %d", runID, refs.LatestSnapshotVersion)
	}
}
