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
			name: "sandbox",
			mode: ExecutorModeSandbox,
			want: ExecutorModeSandbox,
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
			wantErr: `unsupported factory executor mode "remote" (supported: local, sandbox)`,
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

func TestRunSecretSourceConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "env", got: RunSecretSourceEnv, want: "env"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("run secret source = %q, want %q", tt.got, tt.want)
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
		{name: "setup", got: FailureCategorySetup, want: "setup"},
		{name: "engine", got: FailureCategoryEngine, want: "engine"},
		{name: "PRD", got: FailureCategoryPRD, want: "PRD"},
		{name: "run", got: FailureCategoryRun, want: "run"},
		{name: "review", got: FailureCategoryReview, want: "review"},
		{name: "verification", got: FailureCategoryVerification, want: "verification"},
		{name: "CI", got: FailureCategoryCI, want: "CI"},
		{name: "sandbox", got: FailureCategorySandbox, want: "sandbox"},
		{name: "queue", got: FailureCategoryQueue, want: "queue"},
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

func TestSupportedFailureCategories(t *testing.T) {
	want := []string{
		FailureCategorySetup,
		FailureCategoryEngine,
		FailureCategoryPRD,
		FailureCategoryRun,
		FailureCategoryReview,
		FailureCategoryVerification,
		FailureCategoryCI,
		FailureCategorySandbox,
		FailureCategoryQueue,
		FailureCategoryUnknown,
	}
	if got := SupportedFailureCategories(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SupportedFailureCategories() = %#v, want %#v", got, want)
	}
}

func TestNormalizeFailureCategory(t *testing.T) {
	for _, category := range SupportedFailureCategories() {
		category := category
		t.Run(category, func(t *testing.T) {
			if got := NormalizeFailureCategory(category); got != category {
				t.Fatalf("NormalizeFailureCategory(%q) = %q, want %q", category, got, category)
			}
		})
	}

	tests := []struct {
		name     string
		category string
	}{
		{name: "empty", category: ""},
		{name: "whitespace", category: "   "},
		{name: "legacy validation", category: "validation"},
		{name: "legacy pipeline", category: "pipeline"},
		{name: "legacy lowercase ci", category: "ci"},
		{name: "unsupported", category: "database"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeFailureCategory(tt.category); got != FailureCategoryUnknown {
				t.Fatalf("NormalizeFailureCategory(%q) = %q, want %q", tt.category, got, FailureCategoryUnknown)
			}
		})
	}
}

func TestNextActionTypeConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "inspect", got: NextActionTypeInspect, want: "inspect"},
		{name: "takeover", got: NextActionTypeTakeover, want: "takeover"},
		{name: "continue", got: NextActionTypeContinue, want: "continue"},
		{name: "completed", got: NextActionTypeCompleted, want: "completed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("next action type = %q, want %q", tt.got, tt.want)
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
		{name: "policy_decision", got: EventTypePolicyDecision, want: "policy_decision"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("event type = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestNormalizeFailureCategoryForContractV1(t *testing.T) {
	tests := []struct {
		name     string
		category string
		want     string
	}{
		{name: "prd", category: FailureCategoryPRD, want: "validation"},
		{name: "verification", category: FailureCategoryVerification, want: "validation"},
		{name: "run", category: FailureCategoryRun, want: "pipeline"},
		{name: "review", category: FailureCategoryReview, want: "pipeline"},
		{name: "sandbox", category: FailureCategorySandbox, want: "pipeline"},
		{name: "queue", category: FailureCategoryQueue, want: "pipeline"},
		{name: "setup", category: FailureCategorySetup, want: "git"},
		{name: "ci", category: FailureCategoryCI, want: "ci"},
		{name: "legacy ci", category: "ci", want: "ci"},
		{name: "unknown", category: "unsupported", want: FailureCategoryUnknown},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeFailureCategoryForContractV1(tt.category); got != tt.want {
				t.Fatalf("NormalizeFailureCategoryForContractV1(%q) = %q, want %q", tt.category, got, tt.want)
			}
		})
	}
}

func TestSupportedRunDurationSteps(t *testing.T) {
	want := []string{
		RunDurationStepSetup,
		RunDurationStepQueueClaim,
		RunDurationStepSandboxProvision,
		RunDurationStepSandboxStart,
		RunDurationStepEngineRun,
		RunDurationStepReview,
		RunDurationStepVerification,
		RunDurationStepCI,
		RunDurationStepArtifactCollect,
		RunDurationStepFinalization,
	}
	if got := SupportedRunDurationSteps(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SupportedRunDurationSteps() = %#v, want %#v", got, want)
	}
}

func TestDeriveRunTelemetryCompleteTimingData(t *testing.T) {
	base := time.Date(2026, 6, 21, 9, 0, 0, 0, time.UTC)
	finishedAt := base.Add(time.Hour)
	record := RunRecord{
		RunID:      "run-derived-complete",
		CreatedAt:  base,
		FinishedAt: &finishedAt,
	}

	steps := SupportedRunDurationSteps()
	events := make([]EventRecord, 0, len(steps)*2+2)
	events = append(events, EventRecord{
		EventType: EventTypeStepStarted,
		Timestamp: base.Add(30 * time.Second),
		Metadata:  map[string]any{"step": "run"},
	})
	events = append(events, EventRecord{
		EventType: EventTypeStepEnded,
		Timestamp: base.Add(45 * time.Second),
		Metadata:  map[string]any{"step": "run"},
	})
	for i, step := range steps {
		startedAt := base.Add(time.Duration(i+1) * time.Minute)
		finishedAt := startedAt.Add(time.Duration(i+1) * time.Second)
		events = append(events,
			EventRecord{
				EventType: EventTypeStepStarted,
				Timestamp: startedAt,
				Metadata:  map[string]any{"step": step},
			},
			EventRecord{
				EventType: EventTypeStepEnded,
				Timestamp: finishedAt,
				Metadata:  map[string]any{"step": step},
			},
		)
	}

	got := DeriveRunTelemetry(record, events)
	if got == nil || got.TotalDurationMs == nil {
		t.Fatalf("DeriveRunTelemetry() = %#v, want total duration", got)
	}
	if *got.TotalDurationMs != finishedAt.Sub(base).Milliseconds() {
		t.Fatalf("totalDurationMs = %d, want %d", *got.TotalDurationMs, finishedAt.Sub(base).Milliseconds())
	}
	if len(got.StepDurations) != len(steps) {
		t.Fatalf("stepDurations len = %d, want %d: %#v", len(got.StepDurations), len(steps), got.StepDurations)
	}
	for i, step := range steps {
		duration := got.StepDurations[i]
		startedAt := base.Add(time.Duration(i+1) * time.Minute)
		finishedAt := startedAt.Add(time.Duration(i+1) * time.Second)
		if duration.Step != step {
			t.Fatalf("stepDurations[%d].step = %q, want %q", i, duration.Step, step)
		}
		if !duration.StartedAt.Equal(startedAt) {
			t.Fatalf("stepDurations[%d].startedAt = %s, want %s", i, duration.StartedAt, startedAt)
		}
		if !duration.FinishedAt.Equal(finishedAt) {
			t.Fatalf("stepDurations[%d].finishedAt = %s, want %s", i, duration.FinishedAt, finishedAt)
		}
		if duration.DurationMs != finishedAt.Sub(startedAt).Milliseconds() {
			t.Fatalf("stepDurations[%d].durationMs = %d, want %d", i, duration.DurationMs, finishedAt.Sub(startedAt).Milliseconds())
		}
	}
}

func TestDeriveRunTelemetryPartialTimingData(t *testing.T) {
	base := time.Date(2026, 6, 21, 10, 0, 0, 0, time.UTC)
	finishedAt := base.Add(10 * time.Minute)
	record := RunRecord{
		RunID:      "run-derived-partial",
		CreatedAt:  base,
		FinishedAt: &finishedAt,
	}
	events := []EventRecord{
		{
			EventType: EventTypeStepStarted,
			Timestamp: base.Add(1 * time.Minute),
			Metadata:  map[string]any{"step": RunDurationStepSetup},
		},
		{
			EventType: EventTypeStepEnded,
			Timestamp: base.Add(3 * time.Minute),
			Metadata:  map[string]any{"step": RunDurationStepSetup},
		},
		{
			EventType: EventTypeStepStarted,
			Timestamp: base.Add(4 * time.Minute),
			Metadata:  map[string]any{"step": RunDurationStepCI},
		},
		{
			EventType: EventTypeStepEnded,
			Timestamp: base.Add(5 * time.Minute),
			Metadata:  map[string]any{"step": RunDurationStepReview},
		},
		{
			EventType: EventTypeStepStarted,
			Timestamp: time.Time{},
			Metadata:  map[string]any{"step": RunDurationStepFinalization},
		},
	}

	got := DeriveRunTelemetry(record, events)
	if got == nil || got.TotalDurationMs == nil {
		t.Fatalf("DeriveRunTelemetry() = %#v, want total duration", got)
	}
	if *got.TotalDurationMs != finishedAt.Sub(base).Milliseconds() {
		t.Fatalf("totalDurationMs = %d, want %d", *got.TotalDurationMs, finishedAt.Sub(base).Milliseconds())
	}
	if len(got.StepDurations) != 1 {
		t.Fatalf("stepDurations len = %d, want 1: %#v", len(got.StepDurations), got.StepDurations)
	}
	if got.StepDurations[0].Step != RunDurationStepSetup {
		t.Fatalf("stepDurations[0].step = %q, want %q", got.StepDurations[0].Step, RunDurationStepSetup)
	}
}

func TestDeriveRunTelemetryOutOfOrderTimingData(t *testing.T) {
	base := time.Date(2026, 6, 21, 11, 0, 0, 0, time.UTC)
	finishedAt := base.Add(-time.Minute)
	record := RunRecord{
		RunID:      "run-derived-out-of-order",
		CreatedAt:  base,
		FinishedAt: &finishedAt,
	}
	events := []EventRecord{
		{
			EventType: EventTypeStepStarted,
			Timestamp: base.Add(5 * time.Minute),
			Metadata:  map[string]any{"step": RunDurationStepSetup},
		},
		{
			EventType: EventTypeStepEnded,
			Timestamp: base.Add(4 * time.Minute),
			Metadata:  map[string]any{"step": RunDurationStepSetup},
		},
		{
			EventType: EventTypeStepEnded,
			Timestamp: base.Add(6 * time.Minute),
			Metadata:  map[string]any{"step": RunDurationStepReview},
		},
		{
			EventType: EventTypeStepStarted,
			Timestamp: base.Add(7 * time.Minute),
			Metadata:  map[string]any{"step": RunDurationStepCI},
		},
		{
			EventType: EventTypeStepEnded,
			Timestamp: base.Add(9 * time.Minute),
			Metadata:  map[string]any{"step": RunDurationStepCI},
		},
	}

	got := DeriveRunTelemetry(record, events)
	if got == nil {
		t.Fatal("DeriveRunTelemetry() = nil, want valid step duration")
	}
	if got.TotalDurationMs != nil {
		t.Fatalf("totalDurationMs = %d, want omitted for out-of-order run timestamps", *got.TotalDurationMs)
	}
	if len(got.StepDurations) != 1 {
		t.Fatalf("stepDurations len = %d, want 1: %#v", len(got.StepDurations), got.StepDurations)
	}
	if got.StepDurations[0].Step != RunDurationStepCI {
		t.Fatalf("stepDurations[0].step = %q, want %q", got.StepDurations[0].Step, RunDurationStepCI)
	}
	if got.StepDurations[0].DurationMs != 120000 {
		t.Fatalf("stepDurations[0].durationMs = %d, want 120000", got.StepDurations[0].DurationMs)
	}
}

func TestDeriveRunTelemetryPreservesExplicitTimingData(t *testing.T) {
	base := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	finishedAt := base.Add(20 * time.Minute)
	storedTotalDurationMs := int64(42)
	record := RunRecord{
		RunID:      "run-derived-explicit",
		CreatedAt:  base,
		FinishedAt: &finishedAt,
		Telemetry: &RunTelemetry{
			TotalDurationMs: &storedTotalDurationMs,
			StepDurations: []RunStepDuration{
				{
					Step:       RunDurationStepSetup,
					StartedAt:  base.Add(1 * time.Minute),
					FinishedAt: base.Add(2 * time.Minute),
					DurationMs: 60000,
				},
			},
		},
	}
	events := []EventRecord{
		{
			EventType: EventTypeStepStarted,
			Timestamp: base.Add(3 * time.Minute),
			Metadata:  map[string]any{"step": RunDurationStepCI},
		},
		{
			EventType: EventTypeStepEnded,
			Timestamp: base.Add(5 * time.Minute),
			Metadata:  map[string]any{"step": RunDurationStepCI},
		},
	}

	got := DeriveRunTelemetry(record, events)
	if got == nil || got.TotalDurationMs == nil {
		t.Fatalf("DeriveRunTelemetry() = %#v, want explicit telemetry", got)
	}
	if *got.TotalDurationMs != storedTotalDurationMs {
		t.Fatalf("totalDurationMs = %d, want explicit %d", *got.TotalDurationMs, storedTotalDurationMs)
	}
	if len(got.StepDurations) != 1 || got.StepDurations[0].Step != RunDurationStepSetup {
		t.Fatalf("stepDurations = %#v, want explicit setup duration only", got.StepDurations)
	}
	if got == record.Telemetry {
		t.Fatal("DeriveRunTelemetry() returned original telemetry pointer, want copy")
	}
}

func TestDeriveRunTelemetryNormalizesFailureCategory(t *testing.T) {
	record := RunRecord{
		RunID: "run-failed-telemetry-category",
		Telemetry: &RunTelemetry{
			FailureCategory: "database",
		},
		Failure: &FailureSummary{
			Category: FailureCategoryCI,
		},
	}

	got := DeriveRunTelemetry(record, nil)
	if got == nil {
		t.Fatal("DeriveRunTelemetry() = nil, want telemetry")
	}
	if got.FailureCategory != "ci" {
		t.Fatalf("failureCategory = %q, want %q", got.FailureCategory, "ci")
	}

	record.Failure = nil
	got = DeriveRunTelemetry(record, nil)
	if got == nil {
		t.Fatal("DeriveRunTelemetry() = nil, want telemetry")
	}
	if got.FailureCategory != FailureCategoryUnknown {
		t.Fatalf("failureCategory without record failure = %q, want %q", got.FailureCategory, FailureCategoryUnknown)
	}
}

func TestDeriveRunTelemetryPrefersVerificationResultOutcome(t *testing.T) {
	base := time.Date(2026, 6, 21, 18, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		status     string
		stepStatus string
		want       string
	}{
		{name: "warn result beats succeeded step", status: verify.StatusWarn, stepStatus: RunStatusSucceeded, want: verify.StatusWarn},
		{name: "pass result keeps passed vocabulary", status: verify.StatusPass, stepStatus: RunStatusSucceeded, want: "passed"},
		{name: "fail result keeps failed vocabulary", status: verify.StatusFail, stepStatus: RunStatusFailed, want: "failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events := []EventRecord{
				{
					EventType: EventTypeVerificationResult,
					Timestamp: base,
					Metadata:  map[string]any{"status": tt.status},
				},
				{
					EventType: EventTypeStepEnded,
					Timestamp: base.Add(time.Second),
					Metadata: map[string]any{
						"step":   RunDurationStepVerification,
						"status": tt.stepStatus,
					},
				},
			}

			got := DeriveRunTelemetry(RunRecord{RunID: "run-verification-outcome"}, events)
			if got == nil {
				t.Fatal("DeriveRunTelemetry() = nil, want telemetry")
			}
			if got.VerificationOutcome != tt.want {
				t.Fatalf("verificationOutcome = %q, want %q", got.VerificationOutcome, tt.want)
			}
		})
	}
}

func TestFactoryTypesHaveJSONTags(t *testing.T) {
	types := []reflect.Type{
		reflect.TypeOf(RunRecord{}),
		reflect.TypeOf(RunSecretInput{}),
		reflect.TypeOf(RunSecretMetadata{}),
		reflect.TypeOf(SandboxMetadata{}),
		reflect.TypeOf(SandboxConnectionMetadata{}),
		reflect.TypeOf(SourceMetadata{}),
		reflect.TypeOf(ArtifactReference{}),
		reflect.TypeOf(VerificationRecord{}),
		reflect.TypeOf(RunTelemetry{}),
		reflect.TypeOf(RunStepDuration{}),
		reflect.TypeOf(EngineTelemetry{}),
		reflect.TypeOf(RunSandboxTelemetry{}),
		reflect.TypeOf(SandboxCostEstimate{}),
		reflect.TypeOf(FailureSummary{}),
		reflect.TypeOf(HandoffSummary{}),
		reflect.TypeOf(NextAction{}),
		reflect.TypeOf(NextActionLocation{}),
		reflect.TypeOf(QueueEntry{}),
		reflect.TypeOf(QueueClaim{}),
		reflect.TypeOf(EventRecord{}),
		reflect.TypeOf(PolicyDecisionMetadata{}),
		reflect.TypeOf(FactoryPolicy{}),
		reflect.TypeOf(LogChunk{}),
		reflect.TypeOf(BootstrapRequest{}),
		reflect.TypeOf(BootstrapOptions{}),
		reflect.TypeOf(BootstrapResult{}),
		reflect.TypeOf(BootstrapStepResult{}),
		reflect.TypeOf(BootstrapTimelineEvent{}),
		reflect.TypeOf(BootstrapFailure{}),
		reflect.TypeOf(BootstrapCommand{}),
		reflect.TypeOf(BootstrapCommandResult{}),
		reflect.TypeOf(BootstrapToolingCheck{}),
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

func TestBootstrapRequestJSONFields(t *testing.T) {
	original := BootstrapRequest{
		RepositoryURL:   "git@github.com:jywlabs/hal.git",
		BaseBranch:      "main",
		RunBranch:       "hal/factory-remote-workspace-bootstrap",
		WorkspaceDir:    "/workspace/hal",
		RequiredEnvKeys: []string{"GITHUB_TOKEN", "HAL_ENGINE"},
		Env: map[string]string{
			"HAL_ENGINE": "codex",
		},
		Options: BootstrapOptions{
			RefreshHal:         true,
			InstallMissingCLIs: true,
			DryRun:             true,
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
		"repositoryUrl",
		"baseBranch",
		"runBranch",
		"workspaceDir",
		"requiredEnvKeys",
		"env",
		"options",
	} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing bootstrap request JSON field %q", key)
		}
	}

	env, ok := raw["env"].(map[string]any)
	if !ok {
		t.Fatalf("env should be an object, got %T", raw["env"])
	}
	if env["HAL_ENGINE"] != "codex" {
		t.Fatalf("HAL_ENGINE env value = %#v, want codex", env["HAL_ENGINE"])
	}

	options, ok := raw["options"].(map[string]any)
	if !ok {
		t.Fatalf("options should be an object, got %T", raw["options"])
	}
	for _, key := range []string{"refreshHal", "installMissingClis", "dryRun"} {
		if _, ok := options[key]; !ok {
			t.Errorf("missing bootstrap option JSON field %q", key)
		}
	}

	var decoded BootstrapRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(round-trip) error = %v", err)
	}
	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("round-trip mismatch\n got: %#v\nwant: %#v", decoded, original)
	}
}

func TestBootstrapResultJSONFields(t *testing.T) {
	startedAt := time.Date(2026, 6, 20, 20, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(15 * time.Second)
	original := BootstrapResult{
		RepoPath:         "/workspace/hal",
		CheckedOutBranch: "hal/factory-remote-workspace-bootstrap",
		Steps: []BootstrapStepResult{
			{
				Name:           "clone",
				Status:         RunStatusFailed,
				CommandSummary: "git clone <repository> /workspace/hal",
				StartedAt:      startedAt,
				FinishedAt:     &finishedAt,
				ExitCode:       128,
			},
		},
		Timeline: []BootstrapTimelineEvent{
			{
				Timestamp:      finishedAt,
				Step:           "clone",
				Status:         RunStatusFailed,
				Message:        "repository clone failed",
				CommandSummary: "git clone <repository> /workspace/hal",
				OutputSummary:  "remote rejected authentication",
				Metadata: map[string]string{
					"remote": "github",
				},
			},
		},
		Failure: &BootstrapFailure{
			Step:     "clone",
			Category: BootstrapFailureCategoryRepo,
			Message:  "repository clone failed",
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

	for _, key := range []string{"repoPath", "checkedOutBranch", "steps", "timeline", "failure"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing bootstrap result JSON field %q", key)
		}
	}

	steps, ok := raw["steps"].([]any)
	if !ok {
		t.Fatalf("steps should be an array, got %T", raw["steps"])
	}
	if len(steps) != 1 {
		t.Fatalf("steps length = %d, want 1", len(steps))
	}
	step, ok := steps[0].(map[string]any)
	if !ok {
		t.Fatalf("steps[0] should be an object, got %T", steps[0])
	}
	for _, key := range []string{"name", "status", "commandSummary", "startedAt", "finishedAt", "exitCode"} {
		if _, ok := step[key]; !ok {
			t.Errorf("missing bootstrap step JSON field %q", key)
		}
	}

	timeline, ok := raw["timeline"].([]any)
	if !ok {
		t.Fatalf("timeline should be an array, got %T", raw["timeline"])
	}
	if len(timeline) != 1 {
		t.Fatalf("timeline length = %d, want 1", len(timeline))
	}
	event, ok := timeline[0].(map[string]any)
	if !ok {
		t.Fatalf("timeline[0] should be an object, got %T", timeline[0])
	}
	for _, key := range []string{"timestamp", "step", "status", "message", "commandSummary", "outputSummary", "metadata"} {
		if _, ok := event[key]; !ok {
			t.Errorf("missing bootstrap timeline JSON field %q", key)
		}
	}

	failure, ok := raw["failure"].(map[string]any)
	if !ok {
		t.Fatalf("failure should be an object, got %T", raw["failure"])
	}
	for _, key := range []string{"step", "category", "message"} {
		if _, ok := failure[key]; !ok {
			t.Errorf("missing bootstrap failure JSON field %q", key)
		}
	}

	var decoded BootstrapResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(round-trip) error = %v", err)
	}
	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("round-trip mismatch\n got: %#v\nwant: %#v", decoded, original)
	}
}

func TestBootstrapResultOptionalFailureOmitted(t *testing.T) {
	original := BootstrapResult{
		RepoPath:         "/workspace/hal",
		CheckedOutBranch: "hal/factory-remote-workspace-bootstrap",
		Steps:            []BootstrapStepResult{},
		Timeline:         []BootstrapTimelineEvent{},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}

	if _, ok := raw["failure"]; ok {
		t.Errorf("unexpected optional bootstrap failure field in %s", string(data))
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
			Engine:       PolicyEngineCodex,
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
			Sandbox: &SandboxMetadata{
				Name:     "factory-run",
				Provider: "daytona",
				Status:   "running",
				Connection: &SandboxConnectionMetadata{
					Address:           "100.64.0.10",
					PublicIP:          "203.0.113.10",
					TailscaleIP:       "100.64.0.10",
					TailscaleHostname: "factory-run.tailnet.ts.net",
					TailscaleLockdown: true,
				},
				SSHCommand:     "hal sandbox ssh factory-run",
				CleanupCommand: "hal sandbox delete factory-run",
				Handoff:        "Inspect the sandbox before cleanup.",
			},
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
			Telemetry: &RunTelemetry{
				TotalDurationMs: ptrInt64(1200000),
				StepDurations: []RunStepDuration{
					{
						Step:       "run",
						StartedAt:  createdAt.Add(1 * time.Minute),
						FinishedAt: updatedAt,
						DurationMs: 540000,
					},
				},
				Engine: &EngineTelemetry{
					Name:  "codex",
					Model: "gpt-5",
				},
				Sandbox: &RunSandboxTelemetry{
					Provider: "hetzner",
					Size:     "cx22",
				},
				EstimatedSandboxCost: &SandboxCostEstimate{
					AmountUSD: 0.07,
					Estimated: true,
				},
				CIOutcome:           "failed",
				VerificationOutcome: "passed",
				ArtifactCount:       ptrInt(2),
				FailureCategory:     FailureCategoryCI,
			},
			Failure: &FailureSummary{
				Step:             "ci",
				Category:         FailureCategoryCI,
				Message:          "unit tests failed",
				Recoverable:      true,
				SuggestedCommand: "hal factory status 01975515-52ad-7f20-8f10-b35c07051b9f --json",
				ExitCode:         1,
			},
			Secrets: []RunSecretMetadata{
				{Name: "GITHUB_TOKEN", Source: RunSecretSourceEnv, Required: true, Present: true},
			},
		}

		var decoded RunRecord
		requireJSONRoundTrip(t, original, &decoded)
	})

	t.Run("empty telemetry", func(t *testing.T) {
		original := RunRecord{
			RunID:        "run-empty-telemetry",
			Status:       RunStatusSucceeded,
			ExecutorMode: ExecutorModeLocal,
			Source:       SourceMetadata{Kind: SourceKindMarkdown},
			RepoPath:     "/work/hal",
			RepoRemote:   "git@github.com:jywlabs/hal.git",
			BranchName:   "hal/empty-telemetry",
			BaseBranch:   "main",
			CurrentStep:  "done",
			CreatedAt:    createdAt,
			UpdatedAt:    updatedAt,
			Telemetry:    &RunTelemetry{},
		}

		var decoded RunRecord
		requireJSONRoundTrip(t, original, &decoded)
	})

	t.Run("run secret input", func(t *testing.T) {
		original := RunSecretInput{
			Name:     "GITHUB_TOKEN",
			Source:   RunSecretSourceEnv,
			Required: true,
		}

		var decoded RunSecretInput
		requireJSONRoundTrip(t, original, &decoded)
	})

	t.Run("run secret metadata", func(t *testing.T) {
		original := RunSecretMetadata{
			Name:     "GITHUB_TOKEN",
			Source:   RunSecretSourceEnv,
			Required: true,
			Present:  true,
		}

		var decoded RunSecretMetadata
		requireJSONRoundTrip(t, original, &decoded)
	})

	t.Run("failure summary", func(t *testing.T) {
		original := FailureSummary{
			Step:             "review",
			Category:         FailureCategoryReview,
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
		Engine:       PolicyEngineCodex,
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
		Sandbox: &SandboxMetadata{
			Name:     "factory-run",
			Provider: "daytona",
			Status:   "running",
			Connection: &SandboxConnectionMetadata{
				Address:           "100.64.0.10",
				PublicIP:          "203.0.113.10",
				TailscaleIP:       "100.64.0.10",
				TailscaleHostname: "factory-run.tailnet.ts.net",
				TailscaleLockdown: true,
			},
			SSHCommand:     "hal sandbox ssh factory-run",
			CleanupCommand: "hal sandbox delete factory-run",
			Handoff:        "Inspect the sandbox before cleanup.",
		},
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
		Telemetry: &RunTelemetry{
			TotalDurationMs: ptrInt64(1500000),
			StepDurations: []RunStepDuration{
				{
					Step:       "setup",
					StartedAt:  createdAt,
					FinishedAt: createdAt.Add(5 * time.Minute),
					DurationMs: 300000,
				},
				{
					Step:       "run",
					StartedAt:  createdAt.Add(5 * time.Minute),
					FinishedAt: updatedAt,
					DurationMs: 300000,
				},
			},
			Engine: &EngineTelemetry{
				Name:  "codex",
				Model: "gpt-5",
			},
			Sandbox: &RunSandboxTelemetry{
				Provider: "digitalocean",
				Size:     "s-2vcpu-4gb",
			},
			EstimatedSandboxCost: &SandboxCostEstimate{
				AmountUSD: 0.12,
				Estimated: true,
			},
			CIOutcome:           "failed",
			VerificationOutcome: "failed",
			ArtifactCount:       ptrInt(2),
			FailureCategory:     FailureCategoryCI,
		},
		Failure: &FailureSummary{
			Step:             "ci",
			Category:         FailureCategoryCI,
			Message:          "unit tests failed",
			Recoverable:      true,
			SuggestedCommand: "hal factory status 01975515-52ad-7f20-8f10-b35c07051b9f --json",
			ExitCode:         1,
		},
		Secrets: []RunSecretMetadata{
			{Name: "GITHUB_TOKEN", Source: RunSecretSourceEnv, Required: true, Present: true},
			{Name: "NPM_TOKEN", Source: RunSecretSourceEnv, Required: false, Present: false},
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
		"engine",
		"source",
		"repoPath",
		"repoRemote",
		"branchName",
		"baseBranch",
		"sandboxName",
		"sandbox",
		"currentStep",
		"createdAt",
		"updatedAt",
		"finishedAt",
		"artifacts",
		"verification",
		"telemetry",
		"failure",
		"secrets",
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

	telemetry, ok := raw["telemetry"].(map[string]any)
	if !ok {
		t.Fatalf("telemetry should be an object, got %T", raw["telemetry"])
	}
	requireJSONMapKeys(t, telemetry, []string{
		"totalDurationMs", "stepDurations", "engine", "sandbox",
		"estimatedSandboxCost", "ciOutcome", "verificationOutcome",
		"artifactCount", "failureCategory",
	})
	stepDurations, ok := telemetry["stepDurations"].([]any)
	if !ok || len(stepDurations) != 2 {
		t.Fatalf("telemetry.stepDurations should be an array of 2, got %T len %d", telemetry["stepDurations"], len(stepDurations))
	}
	firstStep, ok := stepDurations[0].(map[string]any)
	if !ok {
		t.Fatalf("telemetry.stepDurations[0] should be an object, got %T", stepDurations[0])
	}
	requireJSONMapKeys(t, firstStep, []string{"step", "startedAt", "finishedAt", "durationMs"})
	engine, ok := telemetry["engine"].(map[string]any)
	if !ok {
		t.Fatalf("telemetry.engine should be an object, got %T", telemetry["engine"])
	}
	requireJSONMapKeys(t, engine, []string{"name", "model"})
	sandboxTelemetry, ok := telemetry["sandbox"].(map[string]any)
	if !ok {
		t.Fatalf("telemetry.sandbox should be an object, got %T", telemetry["sandbox"])
	}
	requireJSONMapKeys(t, sandboxTelemetry, []string{"provider", "size"})
	cost, ok := telemetry["estimatedSandboxCost"].(map[string]any)
	if !ok {
		t.Fatalf("telemetry.estimatedSandboxCost should be an object, got %T", telemetry["estimatedSandboxCost"])
	}
	requireJSONMapKeys(t, cost, []string{"amountUsd", "estimated"})

	sandbox, ok := raw["sandbox"].(map[string]any)
	if !ok {
		t.Fatalf("sandbox should be an object, got %T", raw["sandbox"])
	}
	for _, key := range []string{"name", "provider", "status", "connection", "sshCommand", "cleanupCommand", "handoff"} {
		if _, ok := sandbox[key]; !ok {
			t.Errorf("missing sandbox JSON field %q", key)
		}
	}
	connection, ok := sandbox["connection"].(map[string]any)
	if !ok {
		t.Fatalf("sandbox.connection should be an object, got %T", sandbox["connection"])
	}
	for _, key := range []string{"address", "publicIp", "tailscaleIp", "tailscaleHostname", "tailscaleLockdown"} {
		if _, ok := connection[key]; !ok {
			t.Errorf("missing sandbox connection JSON field %q", key)
		}
	}
	for _, forbidden := range []string{"token", "privateKey", "credential", "env", "apiKey"} {
		if _, ok := sandbox[forbidden]; ok {
			t.Errorf("unsafe sandbox field %q should not be serialized", forbidden)
		}
		if _, ok := connection[forbidden]; ok {
			t.Errorf("unsafe sandbox connection field %q should not be serialized", forbidden)
		}
	}

	secrets, ok := raw["secrets"].([]any)
	if !ok {
		t.Fatalf("secrets should be an array, got %T", raw["secrets"])
	}
	if len(secrets) != 2 {
		t.Fatalf("secrets length = %d, want 2", len(secrets))
	}
	firstSecret, ok := secrets[0].(map[string]any)
	if !ok {
		t.Fatalf("secrets[0] should be an object, got %T", secrets[0])
	}
	requireExactJSONKeys(t, firstSecret, []string{"name", "source", "required", "present"})
	if firstSecret["name"] != "GITHUB_TOKEN" {
		t.Fatalf("secret name = %v, want GITHUB_TOKEN", firstSecret["name"])
	}
	if firstSecret["source"] != RunSecretSourceEnv {
		t.Fatalf("secret source = %v, want %s", firstSecret["source"], RunSecretSourceEnv)
	}
	if firstSecret["required"] != true {
		t.Fatalf("secret required = %v, want true", firstSecret["required"])
	}
	if firstSecret["present"] != true {
		t.Fatalf("secret present = %v, want true", firstSecret["present"])
	}
	secondSecret, ok := secrets[1].(map[string]any)
	if !ok {
		t.Fatalf("secrets[1] should be an object, got %T", secrets[1])
	}
	requireExactJSONKeys(t, secondSecret, []string{"name", "source", "required", "present"})
	if secondSecret["present"] != false {
		t.Fatalf("optional secret present = %v, want false", secondSecret["present"])
	}

	var decoded RunRecord
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(round-trip) error = %v", err)
	}
	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("round-trip mismatch\n got: %#v\nwant: %#v", decoded, original)
	}
}

func TestNextActionJSONFields(t *testing.T) {
	original := NextAction{
		ID:             "inspect_factory_run",
		Type:           NextActionTypeTakeover,
		Command:        "hal factory status run-handoff --json",
		Description:    "Inspect the durable run record and timeline.",
		RunID:          "run-handoff",
		SandboxName:    "factory-handoff",
		RepoPath:       "/workspace/hal",
		BranchName:     "hal/factory-handoff",
		PullRequestURL: "https://github.com/jywlabs/hal/pull/42",
		CurrentStep:    "ci",
		FailureReason:  "unit tests failed",
		ArtifactLocations: []NextActionLocation{
			{
				Name:       "prd",
				Path:       ".hal/prd.json",
				StoredPath: "artifacts/run-handoff/hal-prd.json",
			},
		},
		LogLocations: []NextActionLocation{
			{
				Name:       "ci-log",
				Path:       ".hal/reports/ci-output.log",
				StoredPath: "artifacts/run-handoff/hal-reports-ci-output.log",
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

	requireExactJSONKeys(t, raw, []string{
		"id",
		"type",
		"command",
		"description",
		"runId",
		"sandboxName",
		"repoPath",
		"branchName",
		"pullRequestUrl",
		"currentStep",
		"failureReason",
		"artifactLocations",
		"logLocations",
	})

	artifactLocations, ok := raw["artifactLocations"].([]any)
	if !ok || len(artifactLocations) != 1 {
		t.Fatalf("artifactLocations should be one-item array, got %T", raw["artifactLocations"])
	}
	artifactLocation, ok := artifactLocations[0].(map[string]any)
	if !ok {
		t.Fatalf("artifactLocations[0] should be object, got %T", artifactLocations[0])
	}
	requireExactJSONKeys(t, artifactLocation, []string{"name", "path", "storedPath"})

	logLocations, ok := raw["logLocations"].([]any)
	if !ok || len(logLocations) != 1 {
		t.Fatalf("logLocations should be one-item array, got %T", raw["logLocations"])
	}
	logLocation, ok := logLocations[0].(map[string]any)
	if !ok {
		t.Fatalf("logLocations[0] should be object, got %T", logLocations[0])
	}
	requireExactJSONKeys(t, logLocation, []string{"name", "path", "storedPath"})

	var decoded NextAction
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(round-trip) error = %v", err)
	}
	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("round-trip mismatch\n got: %#v\nwant: %#v", decoded, original)
	}
}

func TestNextActionOptionalFieldsOmitted(t *testing.T) {
	original := NextAction{
		ID:          "factory_run_completed",
		Type:        NextActionTypeCompleted,
		Command:     "hal factory status run-complete --json",
		Description: "Inspect the completed durable run record and timeline.",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}

	requireExactJSONKeys(t, raw, []string{"id", "type", "command", "description"})
}

func TestRunRecordSecretMetadataDoesNotSerializeSecretValues(t *testing.T) {
	now := time.Date(2026, 6, 20, 10, 45, 0, 0, time.UTC)
	secretValue := "ghp_factory_secret_value_123"
	secret := RunSecretInput{
		Name:     "GITHUB_TOKEN",
		Source:   RunSecretSourceEnv,
		Required: true,
	}
	record := RunRecord{
		RunID:        "run-secret-safe",
		Status:       RunStatusPending,
		ExecutorMode: ExecutorModeSandbox,
		Source:       SourceMetadata{Kind: SourceKindPRD},
		RepoPath:     "/work/hal",
		RepoRemote:   "git@github.com:jywlabs/hal.git",
		BranchName:   "hal/factory-run-secrets",
		BaseBranch:   "main",
		CurrentStep:  RunStatusPending,
		CreatedAt:    now,
		UpdatedAt:    now,
		Secrets: []RunSecretMetadata{
			secret.Metadata(secretValue != ""),
		},
	}

	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	payload := string(data)
	if strings.Contains(payload, secretValue) {
		t.Fatalf("run record JSON contains raw secret value: %s", payload)
	}
	if strings.Contains(payload, "value") {
		t.Fatalf("run record JSON contains a value field: %s", payload)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}
	secrets, ok := raw["secrets"].([]any)
	if !ok || len(secrets) != 1 {
		t.Fatalf("secrets = %#v, want one secret metadata entry", raw["secrets"])
	}
	metadata, ok := secrets[0].(map[string]any)
	if !ok {
		t.Fatalf("secrets[0] should be an object, got %T", secrets[0])
	}
	requireExactJSONKeys(t, metadata, []string{"name", "source", "required", "present"})
	if metadata["present"] != true {
		t.Fatalf("secret present = %v, want true", metadata["present"])
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
	if decoded.Telemetry != nil {
		t.Fatalf("telemetry = %#v, want nil for omitted legacy field", decoded.Telemetry)
	}
	if decoded.Secrets != nil {
		t.Fatalf("secrets = %#v, want nil for omitted legacy field", decoded.Secrets)
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

func ptrInt(v int) *int {
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

	for _, key := range []string{"engine", "sandboxName", "sandbox", "finishedAt", "artifacts", "verification", "telemetry", "failure", "secrets"} {
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

func TestPolicyDecisionMetadataJSONFields(t *testing.T) {
	original := PolicyDecisionMetadata{
		PolicyField: "factory.policy.verificationRequired",
		Decision:    PolicyDecisionBlockedGate,
		Outcome:     PolicyOutcomeBlocked,
		Reason:      "latest verification result failed",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}

	for _, key := range []string{"policyField", "decision", "outcome", "reason"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing policy decision metadata JSON field %q", key)
		}
	}
	for _, forbidden := range []string{"token", "secret", "credential", "env", "sourcePath", "provider", "apiKey"} {
		if _, ok := raw[forbidden]; ok {
			t.Errorf("unsafe policy decision metadata field %q should not be serialized", forbidden)
		}
	}

	metadata := original.EventMetadata()
	for _, key := range []string{"policyField", "decision", "outcome", "reason"} {
		if _, ok := metadata[key]; !ok {
			t.Errorf("missing policy decision event metadata key %q", key)
		}
	}

	var decoded PolicyDecisionMetadata
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
