//go:build integration
// +build integration

package cmd

import (
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/cloud"
)

func TestCloudLifecycleScenario_RunCancelStatus(t *testing.T) {
	h := setupCloudLifecycleIntegrationHarness(t)
	runner := newCloudLifecycleCommandRunner(h)

	setupFixture := mustLifecycleCheckpointFixture(t, cloudLifecycleCheckpointSetup)
	runFixture := mustLifecycleCheckpointFixture(t, cloudLifecycleCheckpointRun)
	cancelFixture := mustLifecycleCheckpointFixture(t, cloudLifecycleCheckpointCancel)
	statusFixture := mustLifecycleCheckpointFixture(t, cloudLifecycleCheckpointStatus)

	setupResult := runner.Run(cloudLifecycleCommandInvocation{
		Args: lifecycleCommandArgs(t, setupFixture.CommandName),
	})
	if setupResult.Err != nil {
		t.Fatalf("cloud setup failed: %v\noutput:\n%s", setupResult.Err, setupResult.Output)
	}
	assertLifecycleOutputContains(t, setupResult.Output, "Cloud profile configured.")

	tests := []struct {
		name string
		json bool
	}{
		{name: "human output", json: false},
		{name: "json output", json: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runResult := runner.Run(cloudLifecycleCommandInvocation{
				Args: lifecycleCommandArgs(t, runFixture.CommandName),
				JSON: tt.json,
			})
			if runResult.Err != nil {
				t.Fatalf("run --cloud failed: %v\noutput:\n%s", runResult.Err, runResult.Output)
			}

			var runID string
			if tt.json {
				runPayload := mustDecodeLifecycleJSONOutput(t, runResult.Output)
				assertLifecycleRequiredJSONKeys(t, runPayload, runFixture.RequiredJSONKeys)
				runID = mustLifecycleJSONStringField(t, runPayload, cloudLifecycleJSONKeyRunID)
				if got := mustLifecycleJSONStringField(t, runPayload, cloudLifecycleJSONKeyWorkflowKind); got != string(cloud.WorkflowKindRun) {
					t.Fatalf("run workflowKind = %q, want %q", got, cloud.WorkflowKindRun)
				}
			} else {
				assertLifecycleOutputContains(t, runResult.Output, "Run submitted.", "run_id:", "status:")
				runID = mustLifecycleRunIDFromHumanOutput(t, runResult.Output)
			}

			runBeforeCancel := mustLifecycleRunFromHarnessStore(t, h, runID)
			if runBeforeCancel.Status.IsTerminal() {
				t.Fatalf("run %q should be cancellable before cancel, got terminal status %q", runID, runBeforeCancel.Status)
			}

			cancelResult := runner.Run(cloudLifecycleCommandInvocation{
				Args:  lifecycleCommandArgs(t, cancelFixture.CommandName),
				RunID: runID,
				JSON:  tt.json,
			})
			if cancelResult.Err != nil {
				t.Fatalf("cloud cancel failed: %v\noutput:\n%s", cancelResult.Err, cancelResult.Output)
			}

			var cancelStatus string
			if tt.json {
				cancelPayload := mustDecodeLifecycleJSONOutput(t, cancelResult.Output)
				assertLifecycleRequiredJSONKeys(t, cancelPayload, cancelFixture.RequiredJSONKeys)
				if got := mustLifecycleJSONStringField(t, cancelPayload, cloudLifecycleJSONKeyRunID); got != runID {
					t.Fatalf("cancel run ID = %q, want %q", got, runID)
				}
				if !mustLifecycleJSONBoolField(t, cancelPayload, cloudLifecycleJSONKeyCancelRequested) {
					t.Fatalf("cancel output must set %q to true: %v", cloudLifecycleJSONKeyCancelRequested, cancelPayload)
				}
				cancelStatus = mustLifecycleJSONStringField(t, cancelPayload, cloudLifecycleJSONKeyStatus)
			} else {
				assertLifecycleOutputContains(t, cancelResult.Output,
					"Cancel requested.",
					"run_id:",
					runID,
					"cancel_requested: true",
				)
				cancelStatus = mustLifecycleHumanFieldValue(t, cancelResult.Output, "status")
			}

			if cancelStatus != string(cloud.RunStatusCanceled) {
				t.Fatalf("cancel status = %q, want %q", cancelStatus, cloud.RunStatusCanceled)
			}

			statusResult := runner.Run(cloudLifecycleCommandInvocation{
				Args:  lifecycleCommandArgs(t, statusFixture.CommandName),
				RunID: runID,
				JSON:  tt.json,
			})
			if statusResult.Err != nil {
				t.Fatalf("cloud status failed: %v\noutput:\n%s", statusResult.Err, statusResult.Output)
			}

			var statusValue string
			if tt.json {
				statusPayload := mustDecodeLifecycleJSONOutput(t, statusResult.Output)
				assertLifecycleRequiredJSONKeys(t, statusPayload, statusFixture.RequiredJSONKeys)
				if got := mustLifecycleJSONStringField(t, statusPayload, cloudLifecycleJSONKeyRunID); got != runID {
					t.Fatalf("status run ID = %q, want %q", got, runID)
				}
				statusValue = mustLifecycleJSONStringField(t, statusPayload, cloudLifecycleJSONKeyStatus)
			} else {
				assertLifecycleOutputContains(t, statusResult.Output,
					"Run status:",
					"run_id:",
					runID,
					"workflow_kind:",
					string(cloud.WorkflowKindRun),
				)
				statusValue = mustLifecycleHumanFieldValue(t, statusResult.Output, "status")
			}

			if statusValue != string(cloud.RunStatusCanceled) {
				t.Fatalf("status value = %q, want %q", statusValue, cloud.RunStatusCanceled)
			}
			if statusValue != cancelStatus {
				t.Fatalf("cancel/status mismatch: cancel=%q status=%q", cancelStatus, statusValue)
			}

			runAfterCancel := mustLifecycleRunFromHarnessStore(t, h, runID)
			if runAfterCancel.Status != cloud.RunStatusCanceled {
				t.Fatalf("persisted run status = %q, want %q", runAfterCancel.Status, cloud.RunStatusCanceled)
			}
			if !runAfterCancel.Status.IsTerminal() {
				t.Fatalf("persisted run status %q must be terminal", runAfterCancel.Status)
			}
			if !runAfterCancel.CancelRequested {
				t.Fatalf("persisted run %q must have cancel_requested=true", runID)
			}
		})
	}
}

func mustLifecycleHumanFieldValue(t *testing.T, output, field string) string {
	t.Helper()

	prefix := field + ":"
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, prefix))
		if value != "" {
			return value
		}
	}

	t.Fatalf("field %q not found in output:\n%s", field, output)
	return ""
}

func mustLifecycleJSONBoolField(t *testing.T, payload map[string]interface{}, key string) bool {
	t.Helper()

	for _, candidate := range lifecycleJSONKeyCandidates(key) {
		raw, ok := payload[candidate]
		if !ok {
			continue
		}
		value, ok := raw.(bool)
		if !ok {
			t.Fatalf("JSON field %q type = %T, want bool", candidate, raw)
		}
		return value
	}

	t.Fatalf("JSON payload missing bool field %q: %v", key, payload)
	return false
}
