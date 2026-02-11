//go:build integration
// +build integration

package cmd

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
	"github.com/jywlabs/hal/internal/template"
)

func TestCloudLifecycleScenario_RunPullArtifacts(t *testing.T) {
	h := setupCloudLifecycleIntegrationHarness(t)
	runner := newCloudLifecycleCommandRunner(h)

	setupFixture := mustLifecycleCheckpointFixture(t, cloudLifecycleCheckpointSetup)
	runFixture := mustLifecycleCheckpointFixture(t, cloudLifecycleCheckpointRun)
	pullFixture := mustLifecycleCheckpointFixture(t, cloudLifecycleCheckpointPull)
	runWorkflowFixture := mustLifecycleWorkflowFixtureForCommand(t, runFixture.CommandName)

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

	runID := mustLifecycleRunIDFromHumanOutput(t, runResult.Output)
	assertLifecycleRunPersisted(t, h, runID, runWorkflowFixture.ExpectedWorkflowKind)

	run := mustLifecycleRunFromHarnessStore(t, h, runID)
	run.Status = cloud.RunStatusSucceeded
	run.UpdatedAt = time.Now().UTC()
	if !run.Status.IsTerminal() {
		t.Fatalf("run status must be terminal before pull, got %q", run.Status)
	}

	expectedGroups := cloud.WorkflowArtifactGroups(run.WorkflowKind)
	if len(expectedGroups) == 0 {
		t.Fatalf("workflow %q must expose at least one artifact group", run.WorkflowKind)
	}
	expectedArtifactGroup := expectedGroups[0]

	prdPath := filepath.Join(h.HalDir, template.PRDFile)
	progressPath := filepath.Join(h.HalDir, template.ProgressFile)
	if err := os.Remove(prdPath); err != nil {
		t.Fatalf("failed to remove %s before pull: %v", prdPath, err)
	}
	if err := os.Remove(progressPath); err != nil {
		t.Fatalf("failed to remove %s before pull: %v", progressPath, err)
	}

	prdBundlePath := filepath.ToSlash(filepath.Join(template.HalDir, template.PRDFile))
	progressBundlePath := filepath.ToSlash(filepath.Join(template.HalDir, template.ProgressFile))

	pullArgs := append(
		lifecycleCommandArgs(t, pullFixture.CommandName),
		"--artifacts", string(expectedArtifactGroup),
	)

	pullHuman := runner.Run(cloudLifecycleCommandInvocation{
		Args:  pullArgs,
		RunID: runID,
	})
	if pullHuman.Err != nil {
		t.Fatalf("cloud pull (human) failed: %v\noutput:\n%s", pullHuman.Err, pullHuman.Output)
	}
	assertLifecycleOutputContains(t, pullHuman.Output,
		"Snapshot restored successfully.",
		prdBundlePath,
		progressBundlePath,
	)
	assertLifecycleFileContent(t, prdPath, `{"project":"hal","description":"integration harness"}`)
	assertLifecycleFileContent(t, progressPath, "## cloud lifecycle integration harness\n")

	pullJSON := runner.Run(cloudLifecycleCommandInvocation{
		Args:  pullArgs,
		RunID: runID,
		JSON:  true,
	})
	if pullJSON.Err != nil {
		t.Fatalf("cloud pull --json failed: %v\noutput:\n%s", pullJSON.Err, pullJSON.Output)
	}

	pullPayload := mustDecodeLifecycleJSONOutput(t, pullJSON.Output)
	assertLifecycleRequiredJSONKeys(t, pullPayload, pullFixture.RequiredJSONKeys)
	if got := mustLifecycleJSONStringField(t, pullPayload, cloudLifecycleJSONKeyRunID); got != runID {
		t.Fatalf("pull run ID = %q, want %q", got, runID)
	}

	artifactsField := mustLifecycleJSONStringField(t, pullPayload, cloudLifecycleJSONKeyArtifacts)
	artifactGroup := cloud.ArtifactGroup(artifactsField)
	if !artifactGroup.IsValid() {
		t.Fatalf("pull artifacts field %q is not a valid artifact group", artifactsField)
	}
	if !slices.Contains(expectedGroups, artifactGroup) {
		t.Fatalf("pull artifacts group %q does not match workflow %q groups %v", artifactGroup, run.WorkflowKind, expectedGroups)
	}

	restoredPaths := mustLifecycleJSONStringSliceField(t, pullPayload, cloudLifecycleJSONKeyFilesRestored)
	assertLifecycleStringSliceContains(t, restoredPaths, prdBundlePath, progressBundlePath)
}

func mustLifecycleWorkflowFixtureForCommand(t *testing.T, commandName string) cloudLifecycleWorkflowFixture {
	t.Helper()
	for _, fixture := range cloudLifecycleWorkflowFixtures {
		if fixture.CommandName == commandName {
			return fixture
		}
	}
	t.Fatalf("workflow fixture for command %q not found", commandName)
	return cloudLifecycleWorkflowFixture{}
}

func mustLifecycleRunFromHarnessStore(t *testing.T, h *cloudLifecycleIntegrationHarness, runID string) *cloud.Run {
	t.Helper()
	run, err := h.Store.GetRun(context.Background(), runID)
	if err != nil {
		t.Fatalf("failed to load run %q from harness store: %v", runID, err)
	}
	return run
}

func mustLifecycleJSONStringSliceField(t *testing.T, payload map[string]interface{}, key string) []string {
	t.Helper()

	candidates := lifecycleJSONKeyCandidates(key)
	for _, candidate := range candidates {
		raw, ok := payload[candidate]
		if !ok {
			continue
		}

		list, ok := raw.([]interface{})
		if !ok {
			t.Fatalf("JSON field %q type = %T, want []interface{}", candidate, raw)
		}

		values := make([]string, 0, len(list))
		for i, item := range list {
			str, ok := item.(string)
			if !ok {
				t.Fatalf("JSON field %q[%d] type = %T, want string", candidate, i, item)
			}
			values = append(values, str)
		}
		return values
	}

	t.Fatalf("JSON payload missing string slice field %q (checked aliases %v): %v", key, candidates, payload)
	return nil
}

func assertLifecycleStringSliceContains(t *testing.T, values []string, wants ...string) {
	t.Helper()

	for _, want := range wants {
		if !slices.Contains(values, want) {
			t.Fatalf("slice %v missing expected value %q", values, want)
		}
	}
}

func assertLifecycleFileContent(t *testing.T, path, want string) {
	t.Helper()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	if string(got) != want {
		t.Fatalf("content of %s = %q, want %q", path, string(got), want)
	}
}
