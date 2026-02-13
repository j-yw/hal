//go:build integration
// +build integration

package cmd

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
)

func TestWorkerLifecycleCancelScenarios(t *testing.T) {
	statusFixture := mustLifecycleCheckpointFixture(t, cloudLifecycleCheckpointStatus)
	cancelFixture := mustLifecycleCheckpointFixture(t, cloudLifecycleCheckpointCancel)

	for _, workflow := range workerLifecycleWorkflowFixtures {
		workflow := workflow
		runWorkerLifecycleAdapterMatrix(t, "cancel_"+workflow.Name, func(t *testing.T, scenario workerLifecycleAdapterScenario) {
			flow := workerLifecycleFlowForWorkflow(workflow.WorkflowCommand)
			if len(flow) < 6 {
				t.Fatalf("workflow flow must include setup/submit/status/pull/cancel steps, got %d steps", len(flow))
			}

			setupResult := scenario.Runner.Run(workerLifecycleFlowRunInput{Step: flow[0]})
			if setupResult.Err != nil {
				t.Fatalf("setup step failed: %v\noutput:\n%s", setupResult.Err, setupResult.Output)
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

			attemptID := seedWorkerLifecycleCancelableState(t, scenario.Harness, runID)

			cancelResult := scenario.Runner.Run(workerLifecycleFlowRunInput{Step: flow[5], RunID: runID, JSON: true})
			if cancelResult.Err != nil {
				t.Fatalf("cancel step failed: %v\noutput:\n%s", cancelResult.Err, cancelResult.Output)
			}

			cancelPayload := mustDecodeLifecycleJSONOutput(t, cancelResult.Output)
			assertLifecycleRequiredJSONKeys(t, cancelPayload, []string{
				cloudLifecycleJSONKeyRunID,
				cloudLifecycleJSONKeyCancelRequested,
				cloudLifecycleJSONKeyStatus,
			})
			if got := mustLifecycleJSONStringField(t, cancelPayload, cloudLifecycleJSONKeyRunID); got != runID {
				t.Fatalf("cancel runID = %q, want %q", got, runID)
			}
			if !mustLifecycleJSONBoolField(t, cancelPayload, cloudLifecycleJSONKeyCancelRequested) {
				t.Fatalf("cancel output must set %q to true: %v", cloudLifecycleJSONKeyCancelRequested, cancelPayload)
			}
			if got := mustLifecycleJSONStringField(t, cancelPayload, cloudLifecycleJSONKeyStatus); got != string(cloud.RunStatusCanceled) {
				t.Fatalf("cancel status = %q, want %q", got, cloud.RunStatusCanceled)
			}

			terminalizeWorkerLifecycleCanceledAttempt(t, scenario.Harness, attemptID)

			statusResult := scenario.Runner.Run(workerLifecycleFlowRunInput{Step: flow[2], RunID: runID, JSON: true})
			if statusResult.Err != nil {
				t.Fatalf("status step failed: %v\noutput:\n%s", statusResult.Err, statusResult.Output)
			}

			statusPayload := mustDecodeLifecycleJSONOutput(t, statusResult.Output)
			assertLifecycleRequiredJSONKeys(t, statusPayload, statusFixture.RequiredJSONKeys)
			if got := mustLifecycleJSONStringField(t, statusPayload, cloudLifecycleJSONKeyRunID); got != runID {
				t.Fatalf("status runID = %q, want %q", got, runID)
			}
			if got := mustLifecycleJSONStringField(t, statusPayload, cloudLifecycleJSONKeyWorkflowKind); got != string(workflow.WorkflowKind) {
				t.Fatalf("status workflowKind = %q, want %q", got, workflow.WorkflowKind)
			}
			if got := mustLifecycleJSONStringField(t, statusPayload, cloudLifecycleJSONKeyStatus); got != string(cloud.RunStatusCanceled) {
				t.Fatalf("status = %q, want %q", got, cloud.RunStatusCanceled)
			}

			run := mustLifecycleRunFromHarnessStore(t, scenario.Harness, runID)
			if !run.CancelRequested {
				t.Fatalf("persisted run %q must have cancel_requested=true", runID)
			}
			if run.Status != cloud.RunStatusCanceled {
				t.Fatalf("persisted run status = %q, want %q", run.Status, cloud.RunStatusCanceled)
			}
			if !run.Status.IsTerminal() {
				t.Fatalf("persisted run status %q must be terminal", run.Status)
			}

			transitions := scenario.Harness.Store.RunTransitions(runID)
			if len(transitions) == 0 {
				t.Fatalf("run %q has no recorded transitions", runID)
			}
			if got := transitions[len(transitions)-1].To; got != cloud.RunStatusCanceled {
				t.Fatalf("last run transition to = %q, want %q", got, cloud.RunStatusCanceled)
			}

			terminalizations := scenario.Harness.Store.AttemptTerminalizations(runID)
			if len(terminalizations) != 1 {
				t.Fatalf("attempt terminalization count = %d, want 1", len(terminalizations))
			}
			terminalizedAttempt := terminalizations[0]
			if terminalizedAttempt.AttemptID != attemptID {
				t.Fatalf("terminalized attempt ID = %q, want %q", terminalizedAttempt.AttemptID, attemptID)
			}
			if terminalizedAttempt.Status != cloud.AttemptStatusCanceled {
				t.Fatalf("terminalized attempt status = %q, want %q", terminalizedAttempt.Status, cloud.AttemptStatusCanceled)
			}
			if !terminalizedAttempt.Status.IsTerminal() {
				t.Fatalf("terminalized attempt status %q must be terminal", terminalizedAttempt.Status)
			}
		})
	}

	if !cancelFixture.SupportsJSON {
		t.Fatal("cancel checkpoint fixture must support --json")
	}
}

func seedWorkerLifecycleCancelableState(t *testing.T, h *cloudLifecycleIntegrationHarness, runID string) string {
	t.Helper()

	run := mustLifecycleRunFromHarnessStore(t, h, runID)
	run.AttemptCount = 1

	if err := h.Store.TransitionRun(context.Background(), runID, run.Status, cloud.RunStatusClaimed); err != nil {
		t.Fatalf("TransitionRun(%q queued->claimed): %v", runID, err)
	}

	startedAt := time.Now().UTC().Truncate(time.Second)
	attemptID := fmt.Sprintf("%s-attempt-cancel-1", runID)
	attempt := &cloud.Attempt{
		ID:             attemptID,
		RunID:          runID,
		AttemptNumber:  1,
		WorkerID:       "worker-cancel",
		Status:         cloud.AttemptStatusActive,
		StartedAt:      startedAt,
		HeartbeatAt:    startedAt,
		LeaseExpiresAt: startedAt.Add(30 * time.Second),
	}
	if err := h.Store.CreateAttempt(context.Background(), attempt); err != nil {
		t.Fatalf("CreateAttempt(%q): %v", runID, err)
	}

	if err := h.Store.TransitionRun(context.Background(), runID, cloud.RunStatusClaimed, cloud.RunStatusRunning); err != nil {
		t.Fatalf("TransitionRun(%q claimed->running): %v", runID, err)
	}

	return attemptID
}

func terminalizeWorkerLifecycleCanceledAttempt(t *testing.T, h *cloudLifecycleIntegrationHarness, attemptID string) {
	t.Helper()

	errCode := "canceled"
	errMsg := "cancel requested"
	if err := h.Store.TransitionAttempt(
		context.Background(),
		attemptID,
		cloud.AttemptStatusCanceled,
		time.Now().UTC(),
		&errCode,
		&errMsg,
	); err != nil {
		t.Fatalf("TransitionAttempt(%q -> canceled): %v", attemptID, err)
	}
}
