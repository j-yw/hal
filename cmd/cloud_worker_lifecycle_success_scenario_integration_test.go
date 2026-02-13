//go:build integration
// +build integration

package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
	"github.com/jywlabs/hal/internal/template"
)

func TestWorkerLifecycleSuccessScenarios(t *testing.T) {
	for _, workflow := range workerLifecycleWorkflowFixtures {
		workflow := workflow
		runWorkerLifecycleAdapterMatrix(t, "success_"+workflow.Name, func(t *testing.T, scenario workerLifecycleAdapterScenario) {
			flow := workerLifecycleFlowForWorkflow(workflow.WorkflowCommand)
			if len(flow) < 5 {
				t.Fatalf("workflow flow must include setup/submit/status/pull steps, got %d steps", len(flow))
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

			expectedArtifactsByGroup := seedWorkerLifecycleSuccessState(t, scenario.Harness, runID)

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
			assertWorkerLifecyclePullRestoresArtifacts(t, scenario, flow[4], runID, workflow.WorkflowKind, expectedArtifactsByGroup)
		})
	}
}

func seedWorkerLifecycleSuccessState(t *testing.T, h *cloudLifecycleIntegrationHarness, runID string) map[cloud.ArtifactGroup]map[string]string {
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

	expectedArtifactsByGroup := workerLifecycleExpectedArtifactsByGroup(run.WorkflowKind, runID)

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

	seedWorkerLifecycleLatestSnapshot(t, h, runID, latestSnapshotID, latestVersion, workerLifecycleFlattenArtifactFiles(expectedArtifactsByGroup))

	if err := h.Store.UpdateRunSnapshotRefs(ctx, runID, inputSnapshotID, &latestSnapshotID, latestVersion); err != nil {
		t.Fatalf("UpdateRunSnapshotRefs(%q): %v", runID, err)
	}

	return expectedArtifactsByGroup
}

func workerLifecycleExpectedArtifactsByGroup(workflowKind cloud.WorkflowKind, runID string) map[cloud.ArtifactGroup]map[string]string {
	stateFiles := map[string]string{
		filepath.ToSlash(filepath.Join(template.HalDir, template.PRDFile)):      fmt.Sprintf(`{"project":"hal","workflowKind":"%s","runId":"%s"}`, workflowKind, runID),
		filepath.ToSlash(filepath.Join(template.HalDir, template.ProgressFile)): fmt.Sprintf("## %s progress for %s\n", workflowKind, runID),
	}

	artifactsByGroup := map[cloud.ArtifactGroup]map[string]string{
		cloud.ArtifactGroupState: stateFiles,
	}

	switch workflowKind {
	case cloud.WorkflowKindAuto, cloud.WorkflowKindReview:
		reportPath := filepath.ToSlash(filepath.Join(template.HalDir, "reports", fmt.Sprintf("%s-summary.md", workflowKind)))
		artifactsByGroup[cloud.ArtifactGroupReports] = map[string]string{
			reportPath: fmt.Sprintf("# %s report for %s\n", workflowKind, runID),
		}
	}

	return artifactsByGroup
}

func workerLifecycleFlattenArtifactFiles(artifactsByGroup map[cloud.ArtifactGroup]map[string]string) map[string]string {
	flattened := make(map[string]string)
	for _, files := range artifactsByGroup {
		for path, content := range files {
			flattened[path] = content
		}
	}
	return flattened
}

func seedWorkerLifecycleLatestSnapshot(t *testing.T, h *cloudLifecycleIntegrationHarness, runID, snapshotID string, version int, files map[string]string) {
	t.Helper()

	records := make([]cloud.BundleManifestRecord, 0, len(files))
	fileContents := make(map[string][]byte, len(files))
	for path, content := range files {
		contentBytes := []byte(content)
		record := cloud.NewBundleManifestRecord(path, contentBytes)
		records = append(records, record)
		fileContents[record.Path] = contentBytes
	}

	compressed, err := compressBundleFiles(records, fileContents)
	if err != nil {
		t.Fatalf("compressBundleFiles(%q): %v", runID, err)
	}

	manifest := cloud.NewBundleManifest(records)
	snapshot := &cloud.RunStateSnapshot{
		ID:              snapshotID,
		RunID:           runID,
		SnapshotKind:    cloud.SnapshotKindFinal,
		Version:         version,
		SHA256:          manifest.SHA256,
		SizeBytes:       int64(len(compressed)),
		ContentEncoding: "application/gzip",
		ContentBlob:     compressed,
		CreatedAt:       time.Now().UTC(),
	}

	if err := h.Store.PutSnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("PutSnapshot(%q): %v", runID, err)
	}
}

func assertWorkerLifecyclePullRestoresArtifacts(
	t *testing.T,
	scenario workerLifecycleAdapterScenario,
	pullStep workerLifecycleFlowStep,
	runID string,
	workflowKind cloud.WorkflowKind,
	expectedArtifactsByGroup map[cloud.ArtifactGroup]map[string]string,
) {
	t.Helper()

	pullFixture := mustLifecycleCheckpointFixture(t, cloudLifecycleCheckpointPull)
	expectedGroups := cloud.WorkflowArtifactGroups(workflowKind)
	if len(expectedGroups) == 0 {
		t.Fatalf("workflow %q must expose at least one artifact group", workflowKind)
	}

	for _, group := range expectedGroups {
		expectedFiles := expectedArtifactsByGroup[group]
		if len(expectedFiles) == 0 {
			t.Fatalf("missing expected files for workflow %q artifact group %q", workflowKind, group)
		}

		expectedPaths := workerLifecycleSortedArtifactPaths(expectedFiles)
		removeWorkerLifecycleArtifactTargets(t, scenario.Harness.WorkspaceDir, expectedPaths)

		pullStepWithArtifacts := workerLifecycleFlowStep{
			Name:          pullStep.Name,
			RequiresRunID: pullStep.RequiresRunID,
			Args:          append(append([]string(nil), pullStep.Args...), "--artifacts", string(group)),
		}

		pullHuman := scenario.Runner.Run(workerLifecycleFlowRunInput{Step: pullStepWithArtifacts, RunID: runID})
		if pullHuman.Err != nil {
			t.Fatalf("pull step failed for workflow %q artifacts %q: %v\noutput:\n%s", workflowKind, group, pullHuman.Err, pullHuman.Output)
		}
		assertLifecycleOutputContains(t, pullHuman.Output, append([]string{"Snapshot restored successfully."}, expectedPaths...)...)
		assertWorkerLifecycleArtifactFilesReadable(t, scenario.Harness.WorkspaceDir, expectedFiles)

		pullJSON := scenario.Runner.Run(workerLifecycleFlowRunInput{Step: pullStepWithArtifacts, RunID: runID, JSON: true})
		if pullJSON.Err != nil {
			t.Fatalf("pull --json failed for workflow %q artifacts %q: %v\noutput:\n%s", workflowKind, group, pullJSON.Err, pullJSON.Output)
		}

		pullPayload := mustDecodeLifecycleJSONOutput(t, pullJSON.Output)
		assertLifecycleRequiredJSONKeys(t, pullPayload, pullFixture.RequiredJSONKeys)
		if got := mustLifecycleJSONStringField(t, pullPayload, cloudLifecycleJSONKeyRunID); got != runID {
			t.Fatalf("pull runID = %q, want %q", got, runID)
		}
		if got := cloud.ArtifactGroup(mustLifecycleJSONStringField(t, pullPayload, cloudLifecycleJSONKeyArtifacts)); got != group {
			t.Fatalf("pull artifacts = %q, want %q", got, group)
		}

		restoredPaths := mustLifecycleJSONStringSliceField(t, pullPayload, cloudLifecycleJSONKeyFilesRestored)
		assertLifecycleStringSliceContains(t, restoredPaths, expectedPaths...)
	}
}

func workerLifecycleSortedArtifactPaths(files map[string]string) []string {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func removeWorkerLifecycleArtifactTargets(t *testing.T, workspaceDir string, paths []string) {
	t.Helper()

	for _, path := range paths {
		absPath := filepath.Join(workspaceDir, filepath.FromSlash(path))
		if err := os.Remove(absPath); err != nil && !os.IsNotExist(err) {
			t.Fatalf("remove %s before pull: %v", absPath, err)
		}
	}
}

func assertWorkerLifecycleArtifactFilesReadable(t *testing.T, workspaceDir string, files map[string]string) {
	t.Helper()

	for _, path := range workerLifecycleSortedArtifactPaths(files) {
		absPath := filepath.Join(workspaceDir, filepath.FromSlash(path))
		content, err := os.ReadFile(absPath)
		if err != nil {
			t.Fatalf("read %s: %v", absPath, err)
		}
		if string(content) != files[path] {
			t.Fatalf("content of %s = %q, want %q", absPath, string(content), files[path])
		}
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
