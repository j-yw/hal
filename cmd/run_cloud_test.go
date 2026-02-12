package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
)

func TestRunHalRunCloud_SubmitSuccess_Detach_Human(t *testing.T) {
	dir := t.TempDir()
	setupHalDir(t, dir, map[string]string{
		"prd.json":     `{"project":"test"}`,
		"progress.txt": "## progress",
	})

	store := newCloudMockStore()
	store.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")

	flags := &CloudFlags{
		Cloud:            true,
		Detach:           true,
		CloudRepo:        "org/repo",
		CloudBase:        "main",
		CloudAuthProfile: "profile-1",
		CloudAuthScope:   "prd-123",
	}

	var out bytes.Buffer
	err := runHalRunCloud(
		flags,
		dir+"/.hal",
		dir,
		func() (cloud.Store, error) { return store, nil },
		func() cloud.SubmitConfig {
			return cloud.SubmitConfig{IDFunc: func() string { return "run-cloud-001" }}
		},
		&out,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	for _, want := range []string{"Run submitted.", "run_id:", "run-cloud-001", "status:", "queued", "Next: hal cloud status"} {
		if !strings.Contains(output, want) {
			t.Errorf("output does not contain %q\noutput: %s", want, output)
		}
	}
}

func TestRunHalRunCloud_SubmitSuccess_Detach_JSON(t *testing.T) {
	dir := t.TempDir()
	setupHalDir(t, dir, map[string]string{
		"prd.json": `{"project":"test"}`,
	})

	store := newCloudMockStore()
	store.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")

	flags := &CloudFlags{
		Cloud:            true,
		Detach:           true,
		JSON:             true,
		CloudRepo:        "org/repo",
		CloudBase:        "main",
		CloudAuthProfile: "profile-1",
		CloudAuthScope:   "prd-123",
	}

	var out bytes.Buffer
	err := runHalRunCloud(
		flags,
		dir+"/.hal",
		dir,
		func() (cloud.Store, error) { return store, nil },
		func() cloud.SubmitConfig {
			return cloud.SubmitConfig{IDFunc: func() string { return "run-cloud-002" }}
		},
		&out,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp runCloudRunResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &resp); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if resp.RunID != "run-cloud-002" {
		t.Errorf("runId = %q, want %q", resp.RunID, "run-cloud-002")
	}
	if resp.WorkflowKind != "run" {
		t.Errorf("workflowKind = %q, want %q", resp.WorkflowKind, "run")
	}
	if resp.Status != "queued" {
		t.Errorf("status = %q, want %q", resp.Status, "queued")
	}
}

func TestRunHalRunCloud_SubmitSuccess_Wait_Human(t *testing.T) {
	dir := t.TempDir()
	setupHalDir(t, dir, map[string]string{
		"prd.json": `{"project":"test"}`,
	})

	store := newCloudMockStore()
	store.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")

	// Pre-populate the run that will be returned by GetRun after submit.
	// The mock enqueues the run, then we need GetRun to find it.
	// We'll set up the run in runsByID after submit enqueues it.
	runID := "run-cloud-wait"

	flags := &CloudFlags{
		Cloud:            true,
		Wait:             true,
		CloudRepo:        "org/repo",
		CloudBase:        "main",
		CloudAuthProfile: "profile-1",
		CloudAuthScope:   "prd-123",
	}

	// Override poll interval for fast tests.
	origInterval := runCloudPollInterval
	runCloudPollInterval = 10 * time.Millisecond
	t.Cleanup(func() { runCloudPollInterval = origInterval })

	// Make GetRun return a terminal run on first poll.
	store.runsByID[runID] = &cloud.Run{
		ID:            runID,
		Repo:          "org/repo",
		BaseBranch:    "main",
		WorkflowKind:  cloud.WorkflowKindRun,
		Engine:        "claude",
		AuthProfileID: "profile-1",
		ScopeRef:      "prd-123",
		Status:        cloud.RunStatusSucceeded,
		AttemptCount:  1,
		MaxAttempts:   3,
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}

	var out bytes.Buffer
	err := runHalRunCloud(
		flags,
		dir+"/.hal",
		dir,
		func() (cloud.Store, error) { return store, nil },
		func() cloud.SubmitConfig {
			return cloud.SubmitConfig{IDFunc: func() string { return runID }}
		},
		&out,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	for _, want := range []string{"Run submitted.", "Waiting for completion", "Run complete.", "status:", "succeeded", "Next: hal cloud logs"} {
		if !strings.Contains(output, want) {
			t.Errorf("output does not contain %q\noutput: %s", want, output)
		}
	}
}

func TestRunHalRunCloud_SubmitSuccess_Wait_JSON(t *testing.T) {
	dir := t.TempDir()
	setupHalDir(t, dir, map[string]string{
		"prd.json": `{"project":"test"}`,
	})

	store := newCloudMockStore()
	store.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")
	runID := "run-cloud-wait-json"
	store.runsByID[runID] = &cloud.Run{
		ID:            runID,
		Repo:          "org/repo",
		BaseBranch:    "main",
		WorkflowKind:  cloud.WorkflowKindRun,
		Engine:        "claude",
		AuthProfileID: "profile-1",
		ScopeRef:      "prd-123",
		Status:        cloud.RunStatusSucceeded,
		AttemptCount:  1,
		MaxAttempts:   3,
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}

	flags := &CloudFlags{
		Cloud:            true,
		Wait:             true,
		JSON:             true,
		CloudRepo:        "org/repo",
		CloudBase:        "main",
		CloudAuthProfile: "profile-1",
		CloudAuthScope:   "prd-123",
	}

	origInterval := runCloudPollInterval
	runCloudPollInterval = 10 * time.Millisecond
	t.Cleanup(func() { runCloudPollInterval = origInterval })

	var out bytes.Buffer
	err := runHalRunCloud(
		flags,
		dir+"/.hal",
		dir,
		func() (cloud.Store, error) { return store, nil },
		func() cloud.SubmitConfig {
			return cloud.SubmitConfig{IDFunc: func() string { return runID }}
		},
		&out,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp runCloudRunResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &resp); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if resp.RunID != runID {
		t.Errorf("runId = %q, want %q", resp.RunID, runID)
	}
	if resp.WorkflowKind != "run" {
		t.Errorf("workflowKind = %q, want %q", resp.WorkflowKind, "run")
	}
	if resp.Status != "succeeded" {
		t.Errorf("status = %q, want %q", resp.Status, "succeeded")
	}
}

func TestRunHalRunCloud_UsesEngineOverride(t *testing.T) {
	dir := t.TempDir()
	setupHalDir(t, dir, map[string]string{
		"prd.json": `{"project":"test"}`,
		"cloud.yaml": `defaultProfile: default
profiles:
  default:
    engine: claude
`,
	})

	store := newCloudMockStore()
	store.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")

	flags := &CloudFlags{
		Cloud:            true,
		Detach:           true,
		CloudProfile:     "default",
		CloudRepo:        "org/repo",
		CloudBase:        "main",
		CloudAuthProfile: "profile-1",
		CloudAuthScope:   "prd-123",
		Engine:           "pi",
	}

	var out bytes.Buffer
	err := runHalRunCloud(
		flags,
		dir+"/.hal",
		dir,
		func() (cloud.Store, error) { return store, nil },
		func() cloud.SubmitConfig {
			return cloud.SubmitConfig{IDFunc: func() string { return "run-engine-override" }}
		},
		&out,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(store.runs) != 1 {
		t.Fatalf("store.runs count = %d, want 1", len(store.runs))
	}
	if store.runs[0].Engine != "pi" {
		t.Fatalf("submitted engine = %q, want %q", store.runs[0].Engine, "pi")
	}
}

func TestExecuteRunCloud_ForwardsRunEngineFlag(t *testing.T) {
	dir := t.TempDir()
	setupHalDir(t, dir, map[string]string{
		"prd.json": `{"project":"test"}`,
	})

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(cwd)
	})

	store := newCloudMockStore()
	store.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")

	origFlags := runCloudFlags
	origStoreFactory := runCloudStoreFactory
	origConfigFactory := runCloudConfigFactory
	origEngineFlag := engineFlag
	t.Cleanup(func() {
		runCloudFlags = origFlags
		runCloudStoreFactory = origStoreFactory
		runCloudConfigFactory = origConfigFactory
		engineFlag = origEngineFlag
	})

	runCloudFlags = &CloudFlags{
		Cloud:            true,
		Detach:           true,
		CloudRepo:        "org/repo",
		CloudBase:        "main",
		CloudAuthProfile: "profile-1",
		CloudAuthScope:   "prd-123",
	}
	runCloudStoreFactory = func() (cloud.Store, error) { return store, nil }
	runCloudConfigFactory = func() cloud.SubmitConfig {
		return cloud.SubmitConfig{IDFunc: func() string { return "run-engine-forward" }}
	}

	engineFlag = "codex" // Simulate `hal run --cloud --engine codex` / `-e codex`.

	var out bytes.Buffer
	handled, err := executeRunCloud(nil, &out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !handled {
		t.Fatal("executeRunCloud should return handled=true when --cloud is set")
	}

	if len(store.runs) != 1 {
		t.Fatalf("store.runs count = %d, want 1", len(store.runs))
	}
	if store.runs[0].Engine != "codex" {
		t.Fatalf("submitted engine = %q, want %q", store.runs[0].Engine, "codex")
	}
}

func TestRunHalRunCloud_DetachWaitConflict(t *testing.T) {
	flags := &CloudFlags{
		Cloud:  true,
		Detach: true,
		Wait:   true,
	}

	var out bytes.Buffer
	err := runHalRunCloud(
		flags,
		"/nonexistent",
		"/nonexistent",
		nil,
		nil,
		&out,
	)
	if err == nil {
		t.Fatal("expected error for --detach and --wait conflict, got nil")
	}
	if !strings.Contains(err.Error(), "--detach and --wait cannot be used together") {
		t.Errorf("error = %q, want to contain --detach/--wait conflict message", err.Error())
	}
	// Human output must include structured error fields.
	output := out.String()
	if !strings.Contains(output, "error_code: invalid_flag_combination") {
		t.Errorf("human output missing error_code field\noutput: %s", output)
	}
}

func TestRunHalRunCloud_DetachWaitConflict_JSON(t *testing.T) {
	flags := &CloudFlags{
		Cloud:  true,
		Detach: true,
		Wait:   true,
		JSON:   true,
	}

	var out bytes.Buffer
	err := runHalRunCloud(
		flags,
		"/nonexistent",
		"/nonexistent",
		nil,
		nil,
		&out,
	)
	if err != nil {
		t.Fatalf("unexpected error (JSON mode should write to output): %v", err)
	}

	var resp runCloudRunErrorResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &resp); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if resp.ErrorCode != "invalid_flag_combination" {
		t.Errorf("error_code = %q, want %q", resp.ErrorCode, "invalid_flag_combination")
	}
}

func TestRunHalRunCloud_NilStoreFactory_Human(t *testing.T) {
	dir := t.TempDir()
	setupHalDir(t, dir, map[string]string{
		"prd.json": `{"project":"test"}`,
	})

	flags := &CloudFlags{
		Cloud:            true,
		Detach:           true,
		CloudRepo:        "org/repo",
		CloudBase:        "main",
		CloudAuthProfile: "profile-1",
		CloudAuthScope:   "prd-123",
	}

	var out bytes.Buffer
	err := runHalRunCloud(
		flags,
		dir+"/.hal",
		dir,
		nil,
		nil,
		&out,
	)
	if err == nil {
		t.Fatal("expected error for nil store factory, got nil")
	}
	if !strings.Contains(err.Error(), "store not configured") {
		t.Errorf("error = %q, want to contain 'store not configured'", err.Error())
	}
	// Human output must include structured error fields.
	output := out.String()
	if !strings.Contains(output, "error_code: configuration_error") {
		t.Errorf("human output missing error_code field\noutput: %s", output)
	}
}

func TestRunHalRunCloud_NilStoreFactory_JSON(t *testing.T) {
	dir := t.TempDir()
	setupHalDir(t, dir, map[string]string{
		"prd.json": `{"project":"test"}`,
	})

	flags := &CloudFlags{
		Cloud:            true,
		Detach:           true,
		JSON:             true,
		CloudRepo:        "org/repo",
		CloudBase:        "main",
		CloudAuthProfile: "profile-1",
		CloudAuthScope:   "prd-123",
	}

	var out bytes.Buffer
	err := runHalRunCloud(
		flags,
		dir+"/.hal",
		dir,
		nil,
		nil,
		&out,
	)
	if err != nil {
		t.Fatalf("unexpected error (JSON mode): %v", err)
	}

	var resp runCloudRunErrorResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &resp); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if resp.ErrorCode != "configuration_error" {
		t.Errorf("error_code = %q, want %q", resp.ErrorCode, "configuration_error")
	}
}

func TestRunHalRunCloud_StoreFactoryError_JSON(t *testing.T) {
	dir := t.TempDir()
	setupHalDir(t, dir, map[string]string{
		"prd.json": `{"project":"test"}`,
	})

	flags := &CloudFlags{
		Cloud:            true,
		Detach:           true,
		JSON:             true,
		CloudRepo:        "org/repo",
		CloudBase:        "main",
		CloudAuthProfile: "profile-1",
		CloudAuthScope:   "prd-123",
	}

	var out bytes.Buffer
	err := runHalRunCloud(
		flags,
		dir+"/.hal",
		dir,
		func() (cloud.Store, error) { return nil, fmt.Errorf("db down") },
		nil,
		&out,
	)
	if err != nil {
		t.Fatalf("unexpected error (JSON mode): %v", err)
	}

	var resp runCloudRunErrorResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &resp); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if resp.ErrorCode != "configuration_error" {
		t.Errorf("error_code = %q, want %q", resp.ErrorCode, "configuration_error")
	}
}

func TestRunHalRunCloud_SubmitValidationError_JSON(t *testing.T) {
	dir := t.TempDir()
	setupHalDir(t, dir, map[string]string{
		"prd.json": `{"project":"test"}`,
	})

	store := newCloudMockStore()
	store.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")

	flags := &CloudFlags{
		Cloud:            true,
		Detach:           true,
		JSON:             true,
		CloudRepo:        "", // missing repo — will cause validation error
		CloudBase:        "main",
		CloudAuthProfile: "profile-1",
		CloudAuthScope:   "prd-123",
	}

	var out bytes.Buffer
	err := runHalRunCloud(
		flags,
		dir+"/.hal",
		dir,
		func() (cloud.Store, error) { return store, nil },
		func() cloud.SubmitConfig {
			return cloud.SubmitConfig{IDFunc: func() string { return "run-fail" }}
		},
		&out,
	)
	if err != nil {
		t.Fatalf("unexpected error (JSON mode): %v", err)
	}

	var resp runCloudRunErrorResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &resp); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if resp.ErrorCode == "" {
		t.Error("error_code should not be empty for validation error")
	}
	if resp.Error == "" {
		t.Error("error message should not be empty")
	}
}

func TestRunHalRunCloud_MissingHalDir(t *testing.T) {
	flags := &CloudFlags{
		Cloud:            true,
		Detach:           true,
		CloudRepo:        "org/repo",
		CloudBase:        "main",
		CloudAuthProfile: "profile-1",
		CloudAuthScope:   "prd-123",
	}

	var out bytes.Buffer
	err := runHalRunCloud(
		flags,
		"/nonexistent/.hal",
		"/nonexistent",
		nil,
		nil,
		&out,
	)
	if err == nil {
		t.Fatal("expected error for missing .hal directory, got nil")
	}
	if !strings.Contains(err.Error(), ".hal/ not found") {
		t.Errorf("error = %q, want to contain '.hal/ not found'", err.Error())
	}
	// Human output must include structured error fields.
	output := out.String()
	if !strings.Contains(output, "error_code: prerequisite_error") {
		t.Errorf("human output missing error_code field\noutput: %s", output)
	}
}

func TestRunHalRunCloud_JSONRequiredFields(t *testing.T) {
	dir := t.TempDir()
	setupHalDir(t, dir, map[string]string{
		"prd.json": `{"project":"test"}`,
	})

	store := newCloudMockStore()
	store.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")

	flags := &CloudFlags{
		Cloud:            true,
		Detach:           true,
		JSON:             true,
		CloudRepo:        "org/repo",
		CloudBase:        "main",
		CloudAuthProfile: "profile-1",
		CloudAuthScope:   "prd-123",
	}

	var out bytes.Buffer
	err := runHalRunCloud(
		flags,
		dir+"/.hal",
		dir,
		func() (cloud.Store, error) { return store, nil },
		func() cloud.SubmitConfig {
			return cloud.SubmitConfig{IDFunc: func() string { return "run-fields" }}
		},
		&out,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &raw); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	for _, key := range []string{"runId", "workflowKind", "status"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing required JSON key %q", key)
		}
	}
}

func TestRunHalRunCloud_WorkflowKindIsRun(t *testing.T) {
	dir := t.TempDir()
	setupHalDir(t, dir, map[string]string{
		"prd.json": `{"project":"test"}`,
	})

	store := newCloudMockStore()
	store.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")

	flags := &CloudFlags{
		Cloud:            true,
		Detach:           true,
		CloudRepo:        "org/repo",
		CloudBase:        "main",
		CloudAuthProfile: "profile-1",
		CloudAuthScope:   "prd-123",
	}

	var out bytes.Buffer
	err := runHalRunCloud(
		flags,
		dir+"/.hal",
		dir,
		func() (cloud.Store, error) { return store, nil },
		func() cloud.SubmitConfig {
			return cloud.SubmitConfig{IDFunc: func() string { return "run-kind-check" }}
		},
		&out,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the enqueued run has workflowKind=run.
	if len(store.runs) != 1 {
		t.Fatalf("expected 1 enqueued run, got %d", len(store.runs))
	}
	if store.runs[0].WorkflowKind != cloud.WorkflowKindRun {
		t.Errorf("workflowKind = %q, want %q", store.runs[0].WorkflowKind, cloud.WorkflowKindRun)
	}
}

func TestRunHalRunCloud_PrerequisiteFailure_JSON(t *testing.T) {
	flags := &CloudFlags{
		Cloud:            true,
		Detach:           true,
		JSON:             true,
		CloudRepo:        "org/repo",
		CloudBase:        "main",
		CloudAuthProfile: "profile-1",
		CloudAuthScope:   "prd-123",
	}

	var out bytes.Buffer
	err := runHalRunCloud(
		flags,
		"/nonexistent/.hal",
		"/nonexistent",
		nil,
		nil,
		&out,
	)
	if err != nil {
		t.Fatalf("unexpected error (JSON mode): %v", err)
	}

	var resp runCloudRunErrorResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &resp); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if resp.ErrorCode != "prerequisite_error" {
		t.Errorf("error_code = %q, want %q", resp.ErrorCode, "prerequisite_error")
	}
	if resp.Error == "" {
		t.Error("error message should not be empty")
	}
}

func TestExecuteRunCloud_ReturnsFalseWhenNotCloud(t *testing.T) {
	// Save and restore runCloudFlags.
	origFlags := runCloudFlags
	runCloudFlags = &CloudFlags{Cloud: false}
	t.Cleanup(func() { runCloudFlags = origFlags })

	var out bytes.Buffer
	handled, err := executeRunCloud(nil, &out)
	if handled {
		t.Error("executeRunCloud should return false when --cloud is not set")
	}
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestExecuteRunCloud_ReturnsFalseWhenNilFlags(t *testing.T) {
	origFlags := runCloudFlags
	runCloudFlags = nil
	t.Cleanup(func() { runCloudFlags = origFlags })

	var out bytes.Buffer
	handled, err := executeRunCloud(nil, &out)
	if handled {
		t.Error("executeRunCloud should return false when flags are nil")
	}
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- Output contract verification tests ---

func TestRunHalRunCloud_HumanOutputContract_DetachSuccess(t *testing.T) {
	dir := t.TempDir()
	setupHalDir(t, dir, map[string]string{
		"prd.json":     `{"project":"test"}`,
		"progress.txt": "## progress",
	})

	store := newCloudMockStore()
	store.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")

	flags := &CloudFlags{
		Cloud:            true,
		Detach:           true,
		CloudRepo:        "org/repo",
		CloudBase:        "main",
		CloudAuthProfile: "profile-1",
		CloudAuthScope:   "prd-123",
	}

	var out bytes.Buffer
	err := runHalRunCloud(
		flags,
		dir+"/.hal",
		dir,
		func() (cloud.Store, error) { return store, nil },
		func() cloud.SubmitConfig {
			return cloud.SubmitConfig{IDFunc: func() string { return "contract-detach" }}
		},
		&out,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	// AC1: human output includes run ID after submission.
	if !strings.Contains(output, "contract-detach") {
		t.Errorf("output missing run ID\noutput: %s", output)
	}
	// AC1: human output includes status.
	if !strings.Contains(output, "status:") {
		t.Errorf("output missing status field\noutput: %s", output)
	}
	// AC1: human output includes one next-step hint command.
	if !strings.Contains(output, "Next: hal cloud status") {
		t.Errorf("output missing next-step hint\noutput: %s", output)
	}
}

func TestRunHalRunCloud_HumanOutputContract_WaitCompletion(t *testing.T) {
	dir := t.TempDir()
	setupHalDir(t, dir, map[string]string{
		"prd.json": `{"project":"test"}`,
	})

	store := newCloudMockStore()
	store.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")
	runID := "contract-wait"
	store.runsByID[runID] = &cloud.Run{
		ID:            runID,
		Repo:          "org/repo",
		BaseBranch:    "main",
		WorkflowKind:  cloud.WorkflowKindRun,
		Engine:        "claude",
		AuthProfileID: "profile-1",
		ScopeRef:      "prd-123",
		Status:        cloud.RunStatusSucceeded,
		AttemptCount:  1,
		MaxAttempts:   3,
	}

	flags := &CloudFlags{
		Cloud:            true,
		Wait:             true,
		CloudRepo:        "org/repo",
		CloudBase:        "main",
		CloudAuthProfile: "profile-1",
		CloudAuthScope:   "prd-123",
	}

	origInterval := runCloudPollInterval
	runCloudPollInterval = 10 * time.Millisecond
	t.Cleanup(func() { runCloudPollInterval = origInterval })

	var out bytes.Buffer
	err := runHalRunCloud(
		flags,
		dir+"/.hal",
		dir,
		func() (cloud.Store, error) { return store, nil },
		func() cloud.SubmitConfig {
			return cloud.SubmitConfig{IDFunc: func() string { return runID }}
		},
		&out,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	// AC1: run ID after submission.
	if !strings.Contains(output, runID) {
		t.Errorf("output missing run ID\noutput: %s", output)
	}
	// AC1: terminal status at completion.
	if !strings.Contains(output, "succeeded") {
		t.Errorf("output missing terminal status\noutput: %s", output)
	}
	// AC1: one next-step hint command.
	if !strings.Contains(output, "Next: hal cloud logs") {
		t.Errorf("output missing next-step hint\noutput: %s", output)
	}
}

func TestRunHalRunCloud_HumanOutputContract_PrerequisiteFailure(t *testing.T) {
	flags := &CloudFlags{
		Cloud:            true,
		Detach:           true,
		CloudRepo:        "org/repo",
		CloudBase:        "main",
		CloudAuthProfile: "profile-1",
		CloudAuthScope:   "prd-123",
	}

	var out bytes.Buffer
	err := runHalRunCloud(
		flags,
		"/nonexistent/.hal",
		"/nonexistent",
		nil,
		nil,
		&out,
	)
	// AC3: prerequisite failure returns non-zero exit (Go error).
	if err == nil {
		t.Fatal("expected error for prerequisite failure, got nil")
	}

	output := out.String()
	// AC3: human output includes deterministic error code field.
	if !strings.Contains(output, "error_code: prerequisite_error") {
		t.Errorf("human output missing error_code field\noutput: %s", output)
	}
	// AC3: human output includes error message field.
	if !strings.Contains(output, "error:") {
		t.Errorf("human output missing error message field\noutput: %s", output)
	}
}

func TestRunHalRunCloud_JSONOutputContract_ErrorFields(t *testing.T) {
	flags := &CloudFlags{
		Cloud:            true,
		Detach:           true,
		JSON:             true,
		CloudRepo:        "org/repo",
		CloudBase:        "main",
		CloudAuthProfile: "profile-1",
		CloudAuthScope:   "prd-123",
	}

	var out bytes.Buffer
	err := runHalRunCloud(
		flags,
		"/nonexistent/.hal",
		"/nonexistent",
		nil,
		nil,
		&out,
	)
	if err != nil {
		t.Fatalf("unexpected error (JSON mode): %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &raw); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	// AC3: JSON output has error and error_code fields.
	for _, key := range []string{"error", "error_code"} {
		v, ok := raw[key]
		if !ok {
			t.Errorf("missing required JSON key %q", key)
			continue
		}
		if s, ok := v.(string); !ok || s == "" {
			t.Errorf("JSON key %q must be a non-empty string, got %v", key, v)
		}
	}
}

func TestRunHalRunCloud_JSONOutputContract_SuccessFields(t *testing.T) {
	dir := t.TempDir()
	setupHalDir(t, dir, map[string]string{
		"prd.json": `{"project":"test"}`,
	})

	store := newCloudMockStore()
	store.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")

	flags := &CloudFlags{
		Cloud:            true,
		Detach:           true,
		JSON:             true,
		CloudRepo:        "org/repo",
		CloudBase:        "main",
		CloudAuthProfile: "profile-1",
		CloudAuthScope:   "prd-123",
	}

	var out bytes.Buffer
	err := runHalRunCloud(
		flags,
		dir+"/.hal",
		dir,
		func() (cloud.Store, error) { return store, nil },
		func() cloud.SubmitConfig {
			return cloud.SubmitConfig{IDFunc: func() string { return "contract-json" }}
		},
		&out,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &raw); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	// AC2: JSON output has required fields runId, workflowKind, status.
	for _, key := range []string{"runId", "workflowKind", "status"} {
		v, ok := raw[key]
		if !ok {
			t.Errorf("missing required JSON key %q", key)
			continue
		}
		if s, ok := v.(string); !ok || s == "" {
			t.Errorf("JSON key %q must be a non-empty string, got %v", key, v)
		}
	}
	// Verify no error fields in success response.
	for _, key := range []string{"error", "error_code"} {
		if _, ok := raw[key]; ok {
			t.Errorf("success response should not contain %q", key)
		}
	}
}

// --- Secret redaction security tests ---

func stripeLikeSecret() string {
	return strings.Join([]string{"sk", "live", "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"}, "_")
}

// sampleSecrets returns a set of secret values used to verify redaction.
// Each secret matches one of the default redaction rules in internal/cloud/redact.go.
func sampleSecrets() []string {
	return []string{
		"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		"ghp_1234567890abcdefghijklmnopqrstuvwxyz",
		"github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
		stripeLikeSecret(),
	}
}

// assertNoSecrets checks that none of the sample secrets appear in output.
func assertNoSecrets(t *testing.T, output string) {
	t.Helper()
	for _, secret := range sampleSecrets() {
		if strings.Contains(output, secret) {
			t.Errorf("output contains unredacted secret: %s\noutput: %s", secret[:20]+"...", output)
		}
	}
}

func TestRunHalRunCloud_Redact_HumanError(t *testing.T) {
	// Inject a secret into an error message and verify it's redacted in human output.
	secret := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

	var out bytes.Buffer
	_ = writeRunCloudError(&out, false, fmt.Sprintf("store connection failed: auth=%s", secret), "configuration_error")

	output := out.String()
	if strings.Contains(output, "eyJhbGciOiJIUzI1NiI") {
		t.Errorf("human error output contains unredacted JWT\noutput: %s", output)
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Errorf("human error output does not contain [REDACTED] placeholder\noutput: %s", output)
	}
	assertNoSecrets(t, output)
}

func TestRunHalRunCloud_Redact_JSONError(t *testing.T) {
	// Inject a secret into an error message and verify JSON output is valid and redacted.
	secret := "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

	var out bytes.Buffer
	err := writeRunCloudError(&out, true, fmt.Sprintf("auth failed with token %s", secret), "configuration_error")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify output is valid JSON.
	var resp runCloudRunErrorResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &resp); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	output := out.String()
	if strings.Contains(output, secret) {
		t.Errorf("JSON error output contains unredacted GitHub PAT\noutput: %s", output)
	}
	if !strings.Contains(resp.Error, "[REDACTED]") {
		t.Errorf("JSON error field does not contain [REDACTED] placeholder\nerror: %s", resp.Error)
	}
	assertNoSecrets(t, output)
}

func TestRunHalRunCloud_Redact_HumanSuccess(t *testing.T) {
	// Inject a secret into run fields and verify it's redacted in human output.
	secret := stripeLikeSecret()
	run := &cloud.Run{
		ID:           "run-with-secret-" + secret,
		WorkflowKind: cloud.WorkflowKindRun,
		Status:       cloud.RunStatusQueued,
	}

	var out bytes.Buffer
	err := writeRunCloudSuccess(&out, false, run)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	if strings.Contains(output, secret) {
		t.Errorf("human success output contains unredacted Stripe key\noutput: %s", output)
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Errorf("human success output does not contain [REDACTED] placeholder\noutput: %s", output)
	}
	assertNoSecrets(t, output)
}

func TestRunHalRunCloud_Redact_JSONSuccess(t *testing.T) {
	// Inject a secret into run fields and verify JSON output is valid and redacted.
	secret := "github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	run := &cloud.Run{
		ID:           "run-with-pat-" + secret,
		WorkflowKind: cloud.WorkflowKindRun,
		Status:       cloud.RunStatusQueued,
	}

	var out bytes.Buffer
	err := writeRunCloudSuccess(&out, true, run)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify output is valid JSON.
	var resp runCloudRunResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &resp); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	output := out.String()
	if strings.Contains(output, secret) {
		t.Errorf("JSON success output contains unredacted PAT\noutput: %s", output)
	}
	if !strings.Contains(resp.RunID, "[REDACTED]") {
		t.Errorf("JSON runId field does not contain [REDACTED] placeholder\nrunId: %s", resp.RunID)
	}
	assertNoSecrets(t, output)
}

func TestRunHalRunCloud_Redact_HumanTerminal(t *testing.T) {
	// Inject a secret into terminal run output and verify it's redacted.
	secret := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	run := &cloud.Run{
		ID:           "run-terminal-" + secret,
		WorkflowKind: cloud.WorkflowKindRun,
		Status:       cloud.RunStatusSucceeded,
	}

	var out bytes.Buffer
	err := writeRunCloudTerminal(&out, false, run)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	if strings.Contains(output, "eyJhbGciOiJIUzI1NiI") {
		t.Errorf("human terminal output contains unredacted JWT\noutput: %s", output)
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Errorf("human terminal output does not contain [REDACTED] placeholder\noutput: %s", output)
	}
	assertNoSecrets(t, output)
}

func TestRunHalRunCloud_Redact_JSONTerminal(t *testing.T) {
	// Inject a secret into terminal run output and verify JSON is valid and redacted.
	secret := "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
	run := &cloud.Run{
		ID:           "run-terminal-" + secret,
		WorkflowKind: cloud.WorkflowKindRun,
		Status:       cloud.RunStatusFailed,
	}

	var out bytes.Buffer
	err := writeRunCloudTerminal(&out, true, run)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify output is valid JSON.
	var resp runCloudRunResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &resp); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	output := out.String()
	if strings.Contains(output, secret) {
		t.Errorf("JSON terminal output contains unredacted GitHub PAT\noutput: %s", output)
	}
	assertNoSecrets(t, output)
}

func TestRunHalRunCloud_Redact_MultipleSecretsInError(t *testing.T) {
	// Inject multiple secrets into a single error message and verify all are redacted.
	msg := fmt.Sprintf(
		"failed: token=%s key=%s",
		"ghp_1234567890abcdefghijklmnopqrstuvwxyz",
		stripeLikeSecret(),
	)

	// Test human output.
	var humanOut bytes.Buffer
	_ = writeRunCloudError(&humanOut, false, msg, "configuration_error")
	assertNoSecrets(t, humanOut.String())

	// Test JSON output.
	var jsonOut bytes.Buffer
	_ = writeRunCloudError(&jsonOut, true, msg, "configuration_error")

	var resp runCloudRunErrorResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(jsonOut.String())), &resp); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	assertNoSecrets(t, jsonOut.String())
}

func TestRunHalRunCloud_Redact_NoFalsePositive(t *testing.T) {
	// Verify that normal (non-secret) output is not altered by redaction.
	run := &cloud.Run{
		ID:           "run-normal-abc123",
		WorkflowKind: cloud.WorkflowKindRun,
		Status:       cloud.RunStatusQueued,
	}

	var out bytes.Buffer
	err := writeRunCloudSuccess(&out, false, run)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "run-normal-abc123") {
		t.Errorf("normal run ID was incorrectly modified\noutput: %s", output)
	}
	if strings.Contains(output, "[REDACTED]") {
		t.Errorf("normal output should not contain [REDACTED]\noutput: %s", output)
	}
}
