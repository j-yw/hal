package factory

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/verify"
)

func TestRunStatusConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "pending", got: RunStatusPending, want: "pending"},
		{name: "running", got: RunStatusRunning, want: "running"},
		{name: "succeeded", got: RunStatusSucceeded, want: "succeeded"},
		{name: "failed", got: RunStatusFailed, want: "failed"},
		{name: "canceled", got: RunStatusCanceled, want: "canceled"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("status = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestExecutorModeConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "local", got: ExecutorModeLocal, want: "local"},
		{name: "sandbox", got: ExecutorModeSandbox, want: "sandbox"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("executor mode = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestValidateExecutorMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		want    string
		wantErr string
	}{
		{
			name: "local",
			mode: ExecutorModeLocal,
			want: ExecutorModeLocal,
		},
		{
			name:    "empty",
			wantErr: "factory executor mode is required",
		},
		{
			name:    "whitespace",
			mode:    " local ",
			wantErr: `factory executor mode " local " is invalid`,
		},
		{
			name:    "unsupported",
			mode:    "remote",
			wantErr: `unsupported factory executor mode "remote" (supported: local)`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateExecutorMode(tt.mode)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("ValidateExecutorMode() error = nil, want %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ValidateExecutorMode() error = %q, want %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateExecutorMode() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("ValidateExecutorMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestQueueStatusConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "queued", got: QueueStatusQueued, want: "queued"},
		{name: "claimed", got: QueueStatusClaimed, want: "claimed"},
		{name: "succeeded", got: QueueStatusSucceeded, want: "succeeded"},
		{name: "failed", got: QueueStatusFailed, want: "failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("queue status = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestSourceKindConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "auto_discovery", got: SourceKindAutoDiscovery, want: "auto_discovery"},
		{name: "markdown", got: SourceKindMarkdown, want: "markdown"},
		{name: "report", got: SourceKindReport, want: "report"},
		{name: "prd", got: SourceKindPRD, want: "prd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("source kind = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestFailureCategoryConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "validation", got: FailureCategoryValidation, want: "validation"},
		{name: "pipeline", got: FailureCategoryPipeline, want: "pipeline"},
		{name: "engine", got: FailureCategoryEngine, want: "engine"},
		{name: "git", got: FailureCategoryGit, want: "git"},
		{name: "ci", got: FailureCategoryCI, want: "ci"},
		{name: "unknown", got: FailureCategoryUnknown, want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("failure category = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestEventTypeConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "run_created", got: EventTypeRunCreated, want: "run_created"},
		{name: "step_started", got: EventTypeStepStarted, want: "step_started"},
		{name: "step_ended", got: EventTypeStepEnded, want: "step_ended"},
		{name: "command_output_summary", got: EventTypeCommandOutputSummary, want: "command_output_summary"},
		{name: "verification_result", got: EventTypeVerificationResult, want: "verification_result"},
		{name: "ci_state", got: EventTypeCIState, want: "ci_state"},
		{name: "artifact_sync", got: EventTypeArtifactSync, want: "artifact_sync"},
		{name: "failure_classification", got: EventTypeFailureClassification, want: "failure_classification"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("event type = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestFactoryTypesHaveJSONTags(t *testing.T) {
	types := []reflect.Type{
		reflect.TypeOf(RunRecord{}),
		reflect.TypeOf(SourceMetadata{}),
		reflect.TypeOf(ArtifactReference{}),
		reflect.TypeOf(VerificationRecord{}),
		reflect.TypeOf(FailureSummary{}),
		reflect.TypeOf(QueueEntry{}),
		reflect.TypeOf(QueueClaim{}),
		reflect.TypeOf(EventRecord{}),
	}

	for _, typ := range types {
		t.Run(typ.Name(), func(t *testing.T) {
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				if !field.IsExported() {
					continue
				}

				tag, ok := field.Tag.Lookup("json")
				if !ok || tag == "" || tag == "-" {
					t.Errorf("%s.%s missing explicit json tag", typ.Name(), field.Name)
				}
			}
		})
	}
}

func TestFactoryContractTypeRoundTrips(t *testing.T) {
	createdAt := time.Date(2026, 6, 20, 11, 0, 0, 0, time.UTC)
	updatedAt := createdAt.Add(10 * time.Minute)
	finishedAt := createdAt.Add(20 * time.Minute)

	t.Run("run record", func(t *testing.T) {
		original := RunRecord{
			RunID:        "01975515-52ad-7f20-8f10-b35c07051b9f",
			Status:       RunStatusFailed,
			ExecutorMode: ExecutorModeLocal,
			Source: SourceMetadata{
				Kind:       SourceKindMarkdown,
				Path:       ".hal/prd-factory.md",
				ReportPath: ".hal/reports/factory.md",
				Title:      "Factory run records",
			},
			RepoPath:    "/work/hal",
			RepoRemote:  "git@github.com:jywlabs/hal.git",
			BranchName:  "hal/factory-run-records",
			BaseBranch:  "develop",
			SandboxName: "factory-run",
			CurrentStep: "ci",
			CreatedAt:   createdAt,
			UpdatedAt:   updatedAt,
			FinishedAt:  &finishedAt,
			Artifacts: []ArtifactReference{
				{Name: "prd", Type: "json", Path: ".hal/prd.json"},
				{Name: "pull_request", Type: "url", URL: "https://github.com/jywlabs/hal/pull/123"},
			},
			Verification: &VerificationRecord{
				Summary: verify.Summary{
					Total:    3,
					Passed:   1,
					Failed:   1,
					TimedOut: 1,
					Missing:  0,
					Skipped:  0,
					Warnings: 1,
				},
				Artifacts: []verify.ArtifactReference{
					{CheckID: "test", Kind: verify.ArtifactKindStdout, Path: ".hal/reports/verify/test-stdout.txt"},
				},
			},
			Failure: &FailureSummary{
				Step:             "ci",
				Category:         FailureCategoryCI,
				Message:          "unit tests failed",
				Recoverable:      true,
				SuggestedCommand: "hal factory status 01975515-52ad-7f20-8f10-b35c07051b9f --json",
				ExitCode:         1,
			},
		}

		var decoded RunRecord
		requireJSONRoundTrip(t, original, &decoded)
	})

	t.Run("failure summary", func(t *testing.T) {
		original := FailureSummary{
			Step:             "review",
			Category:         FailureCategoryValidation,
			Message:          "review found valid issues",
			Recoverable:      true,
			SuggestedCommand: "hal factory status run-review --json",
			ExitCode:         2,
		}

		var decoded FailureSummary
		requireJSONRoundTrip(t, original, &decoded)
	})

	t.Run("artifact reference", func(t *testing.T) {
		sizeBytes := int64(4096)
		createdAt := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
		original := ArtifactReference{
			ID:         "artifact-pr-report",
			Name:       "pull_request",
			Type:       "url",
			SourcePath: ".hal/reports/pr.md",
			StoredPath: "artifacts/run-123/pr.md",
			Path:       ".hal/reports/pr.md",
			URL:        "https://github.com/jywlabs/hal/pull/123",
			SizeBytes:  &sizeBytes,
			CreatedAt:  &createdAt,
			Summary: map[string]any{
				"status": "merged",
			},
			Warnings: []string{"ci summary was unavailable"},
			Partial:  true,
		}

		var decoded ArtifactReference
		requireJSONRoundTrip(t, original, &decoded)
	})

	t.Run("queue entry", func(t *testing.T) {
		claimedAt := createdAt.Add(2 * time.Minute)
		completedAt := createdAt.Add(15 * time.Minute)
		original := QueueEntry{
			QueueID:      "queue-20260620-0001",
			RunID:        "01975515-52ad-7f20-8f10-b35c07051b9f",
			ExecutorMode: ExecutorModeLocal,
			Status:       QueueStatusFailed,
			CreatedAt:    createdAt,
			ClaimedAt:    &claimedAt,
			CompletedAt:  &completedAt,
			Claim: &QueueClaim{
				WorkerID: "worker-a",
				PID:      4242,
				Hostname: "factory-host",
			},
			AttemptCount: 2,
			LastError:    "unit tests failed",
		}

		var decoded QueueEntry
		requireJSONRoundTrip(t, original, &decoded)
	})

	t.Run("verification record", func(t *testing.T) {
		original := VerificationRecord{
			Summary: verify.Summary{
				Total:    3,
				Passed:   1,
				Failed:   1,
				TimedOut: 1,
				Missing:  0,
				Skipped:  0,
				Warnings: 1,
			},
			Artifacts: []verify.ArtifactReference{
				{CheckID: "test", Kind: verify.ArtifactKindStdout, Path: ".hal/reports/verify/test-stdout.txt"},
			},
		}

		var decoded VerificationRecord
		requireJSONRoundTrip(t, original, &decoded)
	})

	t.Run("timeline event", func(t *testing.T) {
		original := EventRecord{
			Sequence:  42,
			RunID:     "01975515-52ad-7f20-8f10-b35c07051b9f",
			EventType: EventTypeVerificationResult,
			Timestamp: updatedAt,
			Message:   "Browser verification skipped",
			Summary:   "No dev server was running",
			Metadata: map[string]any{
				"check": "browser",
				"ok":    false,
			},
		}

		var decoded EventRecord
		requireJSONRoundTrip(t, original, &decoded)
	})
}

func TestRunRecordJSONFields(t *testing.T) {
	createdAt := time.Date(2026, 6, 20, 9, 30, 0, 0, time.UTC)
	updatedAt := createdAt.Add(10 * time.Minute)
	finishedAt := createdAt.Add(25 * time.Minute)

	original := RunRecord{
		RunID:        "01975515-52ad-7f20-8f10-b35c07051b9f",
		Status:       RunStatusFailed,
		ExecutorMode: ExecutorModeLocal,
		Source: SourceMetadata{
			Kind:       SourceKindMarkdown,
			Path:       ".hal/prd-factory.md",
			ReportPath: ".hal/reports/factory.md",
			Title:      "Factory run records",
		},
		RepoPath:    "/work/hal",
		RepoRemote:  "git@github.com:jywlabs/hal.git",
		BranchName:  "hal/factory-run-records",
		BaseBranch:  "develop",
		SandboxName: "factory-run",
		CurrentStep: "run",
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
		FinishedAt:  &finishedAt,
		Artifacts: []ArtifactReference{
			{
				ID:         "artifact-prd",
				Name:       "prd",
				Type:       "json",
				SourcePath: ".hal/prd.json",
				StoredPath: "artifacts/01975515-52ad-7f20-8f10-b35c07051b9f/prd.json",
				Path:       ".hal/prd.json",
				SizeBytes:  ptrInt64(512),
				CreatedAt:  &createdAt,
				Summary: map[string]any{
					"format": "canonical",
				},
			},
			{
				Name:     "pull_request",
				Type:     "url",
				URL:      "https://github.com/jywlabs/hal/pull/123",
				Warnings: []string{"collected without CI status"},
				Partial:  true,
			},
		},
		Verification: &VerificationRecord{
			Summary: verify.Summary{
				Total:    4,
				Passed:   2,
				Failed:   1,
				TimedOut: 1,
				Missing:  0,
				Skipped:  0,
				Warnings: 1,
			},
			Artifacts: []verify.ArtifactReference{
				{CheckID: "test", Kind: verify.ArtifactKindStdout, Path: ".hal/reports/verify/test-stdout.txt"},
				{CheckID: "test", Kind: verify.ArtifactKindStderr, Path: ".hal/reports/verify/test-stderr.txt"},
			},
		},
		Failure: &FailureSummary{
			Step:             "ci",
			Category:         FailureCategoryCI,
			Message:          "unit tests failed",
			Recoverable:      true,
			SuggestedCommand: "hal factory status 01975515-52ad-7f20-8f10-b35c07051b9f --json",
			ExitCode:         1,
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}

	for _, key := range []string{
		"runId",
		"status",
		"executorMode",
		"source",
		"repoPath",
		"repoRemote",
		"branchName",
		"baseBranch",
		"sandboxName",
		"currentStep",
		"createdAt",
		"updatedAt",
		"finishedAt",
		"artifacts",
		"verification",
		"failure",
	} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing run record JSON field %q", key)
		}
	}

	source, ok := raw["source"].(map[string]any)
	if !ok {
		t.Fatalf("source should be an object, got %T", raw["source"])
	}
	for _, key := range []string{"kind", "path", "reportPath", "title"} {
		if _, ok := source[key]; !ok {
			t.Errorf("missing source JSON field %q", key)
		}
	}

	artifacts, ok := raw["artifacts"].([]any)
	if !ok {
		t.Fatalf("artifacts should be an array, got %T", raw["artifacts"])
	}
	if len(artifacts) != 2 {
		t.Fatalf("artifacts length = %d, want 2", len(artifacts))
	}
	firstArtifact, ok := artifacts[0].(map[string]any)
	if !ok {
		t.Fatalf("artifacts[0] should be an object, got %T", artifacts[0])
	}
	for _, key := range []string{"id", "name", "type", "sourcePath", "storedPath", "path", "sizeBytes", "createdAt", "summary"} {
		if _, ok := firstArtifact[key]; !ok {
			t.Errorf("missing artifact JSON field %q", key)
		}
	}
	secondArtifact, ok := artifacts[1].(map[string]any)
	if !ok {
		t.Fatalf("artifacts[1] should be an object, got %T", artifacts[1])
	}
	if _, ok := secondArtifact["url"]; !ok {
		t.Errorf("missing artifact JSON field %q", "url")
	}
	requireJSONMapKeys(t, secondArtifact, []string{"warnings", "partial"})

	verification, ok := raw["verification"].(map[string]any)
	if !ok {
		t.Fatalf("verification should be an object, got %T", raw["verification"])
	}
	for _, key := range []string{"summary", "artifacts"} {
		if _, ok := verification[key]; !ok {
			t.Errorf("missing verification JSON field %q", key)
		}
	}
	verificationSummary, ok := verification["summary"].(map[string]any)
	if !ok {
		t.Fatalf("verification.summary should be an object, got %T", verification["summary"])
	}
	for _, key := range []string{"total", "passed", "failed", "timedOut", "skipped", "warnings"} {
		if _, ok := verificationSummary[key]; !ok {
			t.Errorf("missing verification summary JSON field %q", key)
		}
	}
	verificationArtifacts, ok := verification["artifacts"].([]any)
	if !ok {
		t.Fatalf("verification.artifacts should be an array, got %T", verification["artifacts"])
	}
	if len(verificationArtifacts) != 2 {
		t.Fatalf("verification.artifacts length = %d, want 2", len(verificationArtifacts))
	}
	firstVerificationArtifact, ok := verificationArtifacts[0].(map[string]any)
	if !ok {
		t.Fatalf("verification.artifacts[0] should be an object, got %T", verificationArtifacts[0])
	}
	for _, key := range []string{"checkId", "kind", "path"} {
		if _, ok := firstVerificationArtifact[key]; !ok {
			t.Errorf("missing verification artifact JSON field %q", key)
		}
	}

	failure, ok := raw["failure"].(map[string]any)
	if !ok {
		t.Fatalf("failure should be an object, got %T", raw["failure"])
	}
	for _, key := range []string{"step", "category", "message", "recoverable", "suggestedCommand", "exitCode"} {
		if _, ok := failure[key]; !ok {
			t.Errorf("missing failure JSON field %q", key)
		}
	}

	var decoded RunRecord
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(round-trip) error = %v", err)
	}
	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("round-trip mismatch\n got: %#v\nwant: %#v", decoded, original)
	}
}

func TestQueueEntryJSONFields(t *testing.T) {
	createdAt := time.Date(2026, 6, 20, 11, 30, 0, 0, time.UTC)
	claimedAt := createdAt.Add(3 * time.Minute)
	completedAt := createdAt.Add(30 * time.Minute)
	original := QueueEntry{
		QueueID:      "queue-20260620-0001",
		RunID:        "run-queue-contract",
		ExecutorMode: ExecutorModeLocal,
		Status:       QueueStatusFailed,
		CreatedAt:    createdAt,
		ClaimedAt:    &claimedAt,
		CompletedAt:  &completedAt,
		Claim: &QueueClaim{
			WorkerID: "worker-a",
			PID:      4242,
			Hostname: "factory-host",
		},
		AttemptCount: 2,
		LastError:    "executor failed",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}

	requireExactJSONKeys(t, raw, []string{
		"queueId",
		"runId",
		"executorMode",
		"status",
		"createdAt",
		"claimedAt",
		"completedAt",
		"claim",
		"attemptCount",
		"lastError",
	})

	claim, ok := raw["claim"].(map[string]any)
	if !ok {
		t.Fatalf("claim should be an object, got %T", raw["claim"])
	}
	requireExactJSONKeys(t, claim, []string{"workerId", "pid", "hostname"})
}

func TestQueueEntryOptionalFieldsOmitted(t *testing.T) {
	original := QueueEntry{
		QueueID:      "queue-20260620-0002",
		RunID:        "run-queued",
		ExecutorMode: ExecutorModeLocal,
		Status:       QueueStatusQueued,
		CreatedAt:    time.Date(2026, 6, 20, 11, 45, 0, 0, time.UTC),
		AttemptCount: 0,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}

	requireExactJSONKeys(t, raw, []string{
		"queueId",
		"runId",
		"executorMode",
		"status",
		"createdAt",
		"attemptCount",
	})
}

func TestRunRecordLoadsWithoutArtifacts(t *testing.T) {
	payload := []byte(`{
		"runId": "run-without-artifacts",
		"status": "succeeded",
		"executorMode": "local",
		"source": {"kind": "markdown", "path": ".hal/prd.md"},
		"repoPath": "/work/hal",
		"repoRemote": "git@github.com:jywlabs/hal.git",
		"branchName": "hal/old-run",
		"baseBranch": "main",
		"currentStep": "done",
		"createdAt": "2026-06-20T09:30:00Z",
		"updatedAt": "2026-06-20T09:45:00Z"
	}`)

	var decoded RunRecord
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(old run record) error = %v", err)
	}

	if decoded.RunID != "run-without-artifacts" {
		t.Fatalf("runId = %q, want run-without-artifacts", decoded.RunID)
	}
	if decoded.Artifacts != nil {
		t.Fatalf("artifacts = %#v, want nil for omitted legacy field", decoded.Artifacts)
	}
}

func requireJSONRoundTrip[T any](t *testing.T, original T, decoded *T) {
	t.Helper()

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if err := json.Unmarshal(data, decoded); err != nil {
		t.Fatalf("json.Unmarshal(round-trip) error = %v", err)
	}
	if !reflect.DeepEqual(*decoded, original) {
		t.Errorf("round-trip mismatch\n got: %#v\nwant: %#v", *decoded, original)
	}
}

func requireExactJSONKeys(t *testing.T, got map[string]any, want []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("JSON keys = %v, want exactly %v", sortedMapKeys(got), want)
	}
	for _, key := range want {
		if _, ok := got[key]; !ok {
			t.Fatalf("missing JSON key %q in %v", key, sortedMapKeys(got))
		}
	}
}

func ptrInt64(v int64) *int64 {
	return &v
}

func requireJSONMapKeys(t *testing.T, raw map[string]any, keys []string) {
	t.Helper()

	for _, key := range keys {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing JSON field %q", key)
		}
	}
}

func sortedMapKeys(got map[string]any) []string {
	keys := make([]string, 0, len(got))
	for key := range got {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func TestRunRecordOptionalFieldsOmitted(t *testing.T) {
	now := time.Date(2026, 6, 20, 10, 0, 0, 0, time.UTC)
	original := RunRecord{
		RunID:        "01975515-b042-7731-8a28-76532001fe4f",
		Status:       RunStatusRunning,
		ExecutorMode: ExecutorModeLocal,
		Source:       SourceMetadata{Kind: SourceKindReport},
		RepoPath:     "/work/hal",
		RepoRemote:   "git@github.com:jywlabs/hal.git",
		BranchName:   "hal/factory-run-records",
		BaseBranch:   "develop",
		CurrentStep:  "run",
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}

	for _, key := range []string{"sandboxName", "finishedAt", "artifacts", "verification", "failure"} {
		if _, ok := raw[key]; ok {
			t.Errorf("unexpected optional field %q in %s", key, string(data))
		}
	}

	source, ok := raw["source"].(map[string]any)
	if !ok {
		t.Fatalf("source should be an object, got %T", raw["source"])
	}
	for _, key := range []string{"path", "reportPath", "title"} {
		if _, ok := source[key]; ok {
			t.Errorf("unexpected optional source field %q in %s", key, string(data))
		}
	}
}

func TestRunRecordCanIncludeVerificationSummaryAndArtifacts(t *testing.T) {
	now := time.Date(2026, 6, 20, 11, 0, 0, 0, time.UTC)
	original := RunRecord{
		RunID:        "run-verification",
		Status:       RunStatusSucceeded,
		ExecutorMode: ExecutorModeLocal,
		Source:       SourceMetadata{Kind: SourceKindMarkdown, Path: ".hal/prd-verify.md"},
		RepoPath:     "/work/hal",
		RepoRemote:   "git@github.com:jywlabs/hal.git",
		BranchName:   "hal/verify",
		BaseBranch:   "main",
		CurrentStep:  "done",
		CreatedAt:    now,
		UpdatedAt:    now,
		Artifacts: []ArtifactReference{
			{Name: "verification-stdout", Type: "text", Path: ".hal/reports/verify/test-stdout.txt"},
			{Name: "verification-stderr", Type: "text", Path: ".hal/reports/verify/test-stderr.txt"},
		},
		Verification: &VerificationRecord{
			Summary: verify.Summary{
				Total:    5,
				Passed:   2,
				Failed:   1,
				TimedOut: 1,
				Missing:  0,
				Skipped:  1,
				Warnings: 1,
			},
			Artifacts: []verify.ArtifactReference{
				{CheckID: "test", Kind: verify.ArtifactKindStdout, Path: ".hal/reports/verify/test-stdout.txt"},
				{CheckID: "lint", Kind: verify.ArtifactKindStderr, Path: ".hal/reports/verify/lint-stderr.txt"},
			},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}
	verification, ok := raw["verification"].(map[string]any)
	if !ok {
		t.Fatalf("verification should be an object, got %T", raw["verification"])
	}
	requireJSONMapKeys(t, verification, []string{"summary", "artifacts"})

	summary, ok := verification["summary"].(map[string]any)
	if !ok {
		t.Fatalf("verification.summary should be an object, got %T", verification["summary"])
	}
	requireJSONMapKeys(t, summary, []string{"total", "passed", "failed", "timedOut", "skipped", "warnings"})
	if summary["total"] != float64(5) {
		t.Fatalf("verification.summary.total = %v, want 5", summary["total"])
	}
	if summary["timedOut"] != float64(1) {
		t.Fatalf("verification.summary.timedOut = %v, want 1", summary["timedOut"])
	}
	if summary["warnings"] != float64(1) {
		t.Fatalf("verification.summary.warnings = %v, want 1", summary["warnings"])
	}

	artifacts, ok := verification["artifacts"].([]any)
	if !ok {
		t.Fatalf("verification.artifacts should be an array, got %T", verification["artifacts"])
	}
	if len(artifacts) != 2 {
		t.Fatalf("verification.artifacts length = %d, want 2", len(artifacts))
	}
	firstArtifact, ok := artifacts[0].(map[string]any)
	if !ok {
		t.Fatalf("verification.artifacts[0] should be an object, got %T", artifacts[0])
	}
	requireJSONMapKeys(t, firstArtifact, []string{"checkId", "kind", "path"})
	if firstArtifact["path"] != ".hal/reports/verify/test-stdout.txt" {
		t.Fatalf("verification artifact path = %v, want .hal/reports/verify/test-stdout.txt", firstArtifact["path"])
	}

	var decoded RunRecord
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(round-trip) error = %v", err)
	}
	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("round-trip mismatch\n got: %#v\nwant: %#v", decoded, original)
	}
}

func TestEventRecordJSONFields(t *testing.T) {
	timestamp := time.Date(2026, 6, 20, 10, 15, 0, 0, time.UTC)
	original := EventRecord{
		Sequence:  7,
		RunID:     "01975515-52ad-7f20-8f10-b35c07051b9f",
		EventType: EventTypeVerificationResult,
		Timestamp: timestamp,
		Message:   "browser verification skipped",
		Summary:   "no dev server was running",
		Metadata: map[string]any{
			"check": "browser",
			"ok":    false,
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}

	for _, key := range []string{"sequence", "runId", "eventType", "timestamp", "message", "summary", "metadata"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing event JSON field %q", key)
		}
	}

	metadata, ok := raw["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("metadata should be an object, got %T", raw["metadata"])
	}
	for _, key := range []string{"check", "ok"} {
		if _, ok := metadata[key]; !ok {
			t.Errorf("missing metadata JSON field %q", key)
		}
	}

	var decoded EventRecord
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(round-trip) error = %v", err)
	}
	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("round-trip mismatch\n got: %#v\nwant: %#v", decoded, original)
	}
}

func TestEventRecordOptionalFieldsOmitted(t *testing.T) {
	timestamp := time.Date(2026, 6, 20, 10, 30, 0, 0, time.UTC)
	original := EventRecord{
		Sequence:  1,
		RunID:     "01975515-52ad-7f20-8f10-b35c07051b9f",
		EventType: EventTypeRunCreated,
		Timestamp: timestamp,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}

	for _, key := range []string{"message", "summary", "metadata"} {
		if _, ok := raw[key]; ok {
			t.Errorf("unexpected optional event field %q in %s", key, string(data))
		}
	}
}
