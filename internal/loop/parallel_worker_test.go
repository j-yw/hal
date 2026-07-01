package loop

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBuildWorkerAssignmentPromptGuardrails(t *testing.T) {
	assignment := WorkerAssignment{
		TaskID:             "TASK-007",
		Title:              "Add worker manifests",
		Description:        "Persist worker results for later aggregation.",
		AcceptanceCriteria: []string{"manifest is JSON", "canonical progress is untouched"},
		PRDFile:            ".hal/parallel/TASK-007/prd.json",
		ProgressFile:       ".hal/parallel/TASK-007/progress.txt",
		ManifestFile:       ".hal/parallel/TASK-007/worker-manifest.json",
		BaseBranch:         "main",
		BranchName:         "hal/parallel-worker-task-007",
		Scheduling: &WorkerSchedulingMetadata{
			Priority:        3,
			Index:           2,
			Total:           5,
			DependsOn:       []string{"TASK-001"},
			ConflictDomains: []string{"internal/loop"},
			ParallelSafe:    boolPtr(true),
			Barrier:         true,
			ParallelReason:  "isolated worker manifest helper",
		},
	}

	prompt := BuildWorkerAssignmentPrompt(assignment)

	required := []string{
		"Implement only this assigned task.",
		"Do not choose the highest-priority task from the PRD.",
		"Implement only task `TASK-007`",
		"Do not edit canonical `.hal/prd.json`.",
		"Do not append canonical `.hal/progress.txt`.",
		"Commit implementation changes on branch `hal/parallel-worker-task-007`",
		"Write a worker manifest JSON file",
		"`taskId`, `status`, `branch`, `commit`, `checks`, `filesChanged`, `progressEntry`, `notes`, and `error`",
		"Manifest `checks` and `filesChanged` MUST be JSON arrays of strings, not objects.",
		`"checks": ["go test ./..."]`,
		`"filesChanged": ["path/to/changed-file"]`,
		"Put the progress summary in the manifest `progressEntry`",
		"Use manifest status `ready_for_integration`",
		".hal/parallel/TASK-007/prd.json",
		".hal/parallel/TASK-007/progress.txt",
		".hal/parallel/TASK-007/worker-manifest.json",
		"manifest is JSON",
		"canonical progress is untouched",
		"Depends on: TASK-001",
		"Conflict domains: internal/loop",
		"Parallel safe: true",
		"Barrier task: true",
		"Parallel reason: isolated worker manifest helper",
	}
	for _, want := range required {
		if !strings.Contains(prompt, want) {
			t.Fatalf("prompt missing %q:\n%s", want, prompt)
		}
	}
}

func TestWorkerManifestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "worker-manifest.json")

	want := WorkerManifest{
		TaskID:        "TASK-007",
		Status:        WorkerManifestStatusReadyForIntegration,
		Branch:        "hal/parallel-worker-task-007",
		Commit:        "abc1234",
		Checks:        []string{"go test ./internal/loop"},
		FilesChanged:  []string{"internal/loop/parallel_worker.go"},
		ProgressEntry: "- TASK-007: implemented worker manifest primitives",
		Notes:         "ready for aggregation",
	}

	if err := WriteWorkerManifest(path, want); err != nil {
		t.Fatalf("WriteWorkerManifest() error = %v", err)
	}

	got, err := ReadWorkerManifest(path)
	if err != nil {
		t.Fatalf("ReadWorkerManifest() error = %v", err)
	}
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("manifest round-trip mismatch:\ngot:  %#v\nwant: %#v", *got, want)
	}

	tempFiles, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".worker-manifest.json.tmp-*"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(tempFiles) != 0 {
		t.Fatalf("temporary files were not cleaned up: %v", tempFiles)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("manifest JSON is invalid: %v", err)
	}
	for _, key := range []string{"taskId", "status", "branch", "commit", "checks", "filesChanged", "progressEntry", "notes", "error"} {
		if _, ok := raw[key]; !ok {
			t.Fatalf("manifest JSON missing key %q in %s", key, string(data))
		}
	}
}

func TestReadWorkerManifestNormalizesRealEngineStringListDrift(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "worker-manifest.json")
	data := []byte(`{
  "taskId": "TASK-007",
  "status": "ready_for_integration",
  "branch": "hal/parallel-worker-task-007",
  "commit": "abc1234",
  "checks": {
    "typecheck": "not run - no typecheck configured",
    "tests": true
  },
  "filesChanged": "internal/loop/parallel_worker.go",
  "progressEntry": "- TASK-007: implemented worker manifest primitives",
  "notes": "ready for aggregation",
  "error": ""
}`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	got, err := ReadWorkerManifest(path)
	if err != nil {
		t.Fatalf("ReadWorkerManifest() error = %v", err)
	}

	wantChecks := []string{"tests: true", "typecheck: not run - no typecheck configured"}
	if !reflect.DeepEqual(got.Checks, wantChecks) {
		t.Fatalf("Checks = %#v, want %#v", got.Checks, wantChecks)
	}
	if !reflect.DeepEqual(got.FilesChanged, []string{"internal/loop/parallel_worker.go"}) {
		t.Fatalf("FilesChanged = %#v, want normalized single string", got.FilesChanged)
	}
}

func boolPtr(value bool) *bool {
	return &value
}

func TestWriteWorkerManifestRequiresPath(t *testing.T) {
	if err := WriteWorkerManifest("", WorkerManifest{}); err == nil {
		t.Fatal("WriteWorkerManifest() error = nil, want path validation error")
	}
}
