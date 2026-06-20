package factory

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
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
		reflect.TypeOf(FailureSummary{}),
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

func TestRunRecordJSONFields(t *testing.T) {
	createdAt := time.Date(2026, 6, 20, 9, 30, 0, 0, time.UTC)
	updatedAt := createdAt.Add(10 * time.Minute)
	finishedAt := createdAt.Add(25 * time.Minute)

	original := RunRecord{
		RunID:  "01975515-52ad-7f20-8f10-b35c07051b9f",
		Status: RunStatusFailed,
		Source: SourceMetadata{
			Kind:       "markdown",
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
				Name: "prd",
				Type: "json",
				Path: ".hal/prd.json",
			},
			{
				Name: "pull_request",
				Type: "url",
				URL:  "https://github.com/jywlabs/hal/pull/123",
			},
		},
		Failure: &FailureSummary{
			Step:        "ci",
			Category:    "test",
			Message:     "unit tests failed",
			Recoverable: true,
			ExitCode:    1,
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
	for _, key := range []string{"name", "type", "path"} {
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

	failure, ok := raw["failure"].(map[string]any)
	if !ok {
		t.Fatalf("failure should be an object, got %T", raw["failure"])
	}
	for _, key := range []string{"step", "category", "message", "recoverable", "exitCode"} {
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

func TestRunRecordOptionalFieldsOmitted(t *testing.T) {
	now := time.Date(2026, 6, 20, 10, 0, 0, 0, time.UTC)
	original := RunRecord{
		RunID:       "01975515-b042-7731-8a28-76532001fe4f",
		Status:      RunStatusRunning,
		Source:      SourceMetadata{Kind: "report"},
		RepoPath:    "/work/hal",
		RepoRemote:  "git@github.com:jywlabs/hal.git",
		BranchName:  "hal/factory-run-records",
		BaseBranch:  "develop",
		CurrentStep: "run",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}

	for _, key := range []string{"sandboxName", "finishedAt", "artifacts", "failure"} {
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
