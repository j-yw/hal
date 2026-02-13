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

const (
	workerLifecycleProfileRevokedEventType    = "profile_revoked"
	workerLifecycleProfileRevokedErrorCode    = "profile_revoked"
	workerLifecycleProfileRevokedErrorMessage = "auth profile revoked during heartbeat renewal"
)

func TestWorkerLifecycleProfileRevokedScenarios(t *testing.T) {
	statusFixture := mustLifecycleCheckpointFixture(t, cloudLifecycleCheckpointStatus)

	for _, workflow := range workerLifecycleWorkflowFixtures {
		workflow := workflow
		runWorkerLifecycleAdapterMatrix(t, "profile_revoked_"+workflow.Name, func(t *testing.T, scenario workerLifecycleAdapterScenario) {
			flow := workerLifecycleFlowForWorkflow(workflow.WorkflowCommand)
			if len(flow) < 4 {
				t.Fatalf("workflow flow must include setup/submit/status/logs steps, got %d steps", len(flow))
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

			attemptID := seedWorkerLifecycleProfileRevokedState(t, scenario.Harness, runID)
			releaseAuthLockCalls := terminalizeWorkerLifecycleProfileRevokedAttempt(t, scenario.Harness, runID, attemptID)
			if releaseAuthLockCalls != 1 {
				t.Fatalf("ReleaseAuthLock call count = %d, want 1", releaseAuthLockCalls)
			}

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
			if got := mustLifecycleJSONStringField(t, statusPayload, cloudLifecycleJSONKeyStatus); got != string(cloud.RunStatusFailed) {
				t.Fatalf("status = %q, want %q", got, cloud.RunStatusFailed)
			}

			assertWorkerLifecycleProfileRevokedTerminalState(t, scenario.Harness, runID, attemptID)
		})
	}
}

func seedWorkerLifecycleProfileRevokedState(t *testing.T, h *cloudLifecycleIntegrationHarness, runID string) string {
	t.Helper()

	run := mustLifecycleRunFromHarnessStore(t, h, runID)
	run.AttemptCount = 1

	if err := h.Store.TransitionRun(context.Background(), runID, run.Status, cloud.RunStatusClaimed); err != nil {
		t.Fatalf("TransitionRun(%q queued->claimed): %v", runID, err)
	}

	startedAt := time.Now().UTC().Truncate(time.Second)
	attemptID := fmt.Sprintf("%s-attempt-profile-revoked-1", runID)
	attempt := &cloud.Attempt{
		ID:             attemptID,
		RunID:          runID,
		AttemptNumber:  1,
		WorkerID:       "worker-profile-revoked",
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

type workerLifecycleProfileRevokedErrNotFoundStore struct {
	*cloudLifecycleHarnessStore
	releaseAuthLockCalls int
}

func (s *workerLifecycleProfileRevokedErrNotFoundStore) ReleaseAuthLock(_ context.Context, _, _ string, _ time.Time) error {
	s.releaseAuthLockCalls++
	return cloud.ErrNotFound
}

func terminalizeWorkerLifecycleProfileRevokedAttempt(t *testing.T, h *cloudLifecycleIntegrationHarness, runID, attemptID string) int {
	t.Helper()

	run := mustLifecycleRunFromHarnessStore(t, h, runID)
	if run.AuthProfileID == "" {
		t.Fatalf("run %q has empty auth profile ID", runID)
	}

	profile, err := h.Store.GetAuthProfile(context.Background(), run.AuthProfileID)
	if err != nil {
		t.Fatalf("GetAuthProfile(%q): %v", run.AuthProfileID, err)
	}
	profile.Status = cloud.AuthProfileStatusRevoked
	if err := h.Store.UpdateAuthProfile(context.Background(), profile); err != nil {
		t.Fatalf("UpdateAuthProfile(%q): %v", run.AuthProfileID, err)
	}

	store := &workerLifecycleProfileRevokedErrNotFoundStore{cloudLifecycleHarnessStore: h.Store}
	heartbeat := cloud.NewHeartbeatService(store, cloud.HeartbeatConfig{
		IDFunc: func() string { return fmt.Sprintf("%s-profile-revoked", runID) },
	})

	err = heartbeat.Renew(context.Background(), attemptID, run.AuthProfileID, runID)
	if !cloud.IsProfileRevoked(err) {
		t.Fatalf("HeartbeatService.Renew(%q) error = %v, want profile_revoked", runID, err)
	}

	if err := h.Store.TransitionRun(context.Background(), runID, cloud.RunStatusRunning, cloud.RunStatusFailed); err != nil {
		t.Fatalf("TransitionRun(%q running->failed): %v", runID, err)
	}

	return store.releaseAuthLockCalls
}

func assertWorkerLifecycleProfileRevokedTerminalState(t *testing.T, h *cloudLifecycleIntegrationHarness, runID, attemptID string) {
	t.Helper()

	run := mustLifecycleRunFromHarnessStore(t, h, runID)
	if run.Status != cloud.RunStatusFailed {
		t.Fatalf("persisted run status = %q, want %q", run.Status, cloud.RunStatusFailed)
	}
	if !run.Status.IsTerminal() {
		t.Fatalf("persisted run status %q must be terminal", run.Status)
	}

	transitions := h.Store.RunTransitions(runID)
	if len(transitions) == 0 {
		t.Fatalf("run %q has no recorded transitions", runID)
	}
	lastTransition := transitions[len(transitions)-1]
	if lastTransition.To != cloud.RunStatusFailed {
		t.Fatalf("last run transition = %q -> %q, want terminal to %q", lastTransition.From, lastTransition.To, cloud.RunStatusFailed)
	}

	if got := h.Store.AttemptTerminalizationCount(runID); got != 1 {
		t.Fatalf("AttemptTerminalizationCount(%q) = %d, want 1", runID, got)
	}
	terminalizations := h.Store.AttemptTerminalizations(runID)
	terminalization := terminalizations[0]
	if terminalization.AttemptID != attemptID {
		t.Fatalf("terminalized attempt ID = %q, want %q", terminalization.AttemptID, attemptID)
	}
	if terminalization.Status != cloud.AttemptStatusFailed {
		t.Fatalf("terminalized attempt status = %q, want %q", terminalization.Status, cloud.AttemptStatusFailed)
	}
	if !terminalization.Status.IsTerminal() {
		t.Fatalf("terminalized attempt status %q must be terminal", terminalization.Status)
	}
	if terminalization.ErrorCode == nil || *terminalization.ErrorCode != workerLifecycleProfileRevokedErrorCode {
		t.Fatalf("terminalized attempt error code = %v, want %q", terminalization.ErrorCode, workerLifecycleProfileRevokedErrorCode)
	}
	if terminalization.ErrorMessage == nil || *terminalization.ErrorMessage != workerLifecycleProfileRevokedErrorMessage {
		t.Fatalf("terminalized attempt error message = %v, want %q", terminalization.ErrorMessage, workerLifecycleProfileRevokedErrorMessage)
	}
	if terminalization.EndedAt.IsZero() {
		t.Fatalf("terminalized attempt endedAt must be set for run %q", runID)
	}

	persistedAttempt, err := h.Store.GetAttempt(context.Background(), attemptID)
	if err != nil {
		t.Fatalf("GetAttempt(%q): %v", attemptID, err)
	}
	if persistedAttempt.Status != cloud.AttemptStatusFailed {
		t.Fatalf("persisted attempt status = %q, want %q", persistedAttempt.Status, cloud.AttemptStatusFailed)
	}
	if persistedAttempt.EndedAt == nil || persistedAttempt.EndedAt.IsZero() {
		t.Fatalf("persisted attempt EndedAt must be set: %#v", persistedAttempt)
	}
	if persistedAttempt.ErrorCode == nil || *persistedAttempt.ErrorCode != workerLifecycleProfileRevokedErrorCode {
		t.Fatalf("persisted attempt error code = %v, want %q", persistedAttempt.ErrorCode, workerLifecycleProfileRevokedErrorCode)
	}
	if persistedAttempt.ErrorMessage == nil || *persistedAttempt.ErrorMessage != workerLifecycleProfileRevokedErrorMessage {
		t.Fatalf("persisted attempt error message = %v, want %q", persistedAttempt.ErrorMessage, workerLifecycleProfileRevokedErrorMessage)
	}

	if _, err := h.Store.GetActiveAttemptByRun(context.Background(), runID); !cloud.IsNotFound(err) {
		t.Fatalf("expected active attempt to be cleared for run %q, err = %v", runID, err)
	}

	events, err := h.Store.ListEvents(context.Background(), runID)
	if err != nil {
		t.Fatalf("ListEvents(%q): %v", runID, err)
	}
	foundProfileRevokedEvent := false
	for _, event := range events {
		if event != nil && event.EventType == workerLifecycleProfileRevokedEventType {
			foundProfileRevokedEvent = true
			break
		}
	}
	if !foundProfileRevokedEvent {
		t.Fatalf("run %q missing %q event in timeline: %#v", runID, workerLifecycleProfileRevokedEventType, events)
	}
}
