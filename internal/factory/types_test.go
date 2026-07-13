package factory

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
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
		{name: "succeeded with warnings", got: RunStatusSucceededWithWarnings, want: "succeeded_with_warnings"},
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

func TestPublishRunnerConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "host", got: PublishRunnerHost, want: "host"},
		{name: "sandbox", got: PublishRunnerSandbox, want: "sandbox"},
		{name: "auto", got: PublishRunnerAuto, want: "auto"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("publish runner = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestSupportedPublishRunners(t *testing.T) {
	want := []string{PublishRunnerHost, PublishRunnerSandbox, PublishRunnerAuto}
	if got := SupportedPublishRunners(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SupportedPublishRunners() = %#v, want %#v", got, want)
	}
}

func TestNormalizePublishRunner(t *testing.T) {
	if got := NormalizePublishRunner(" Sandbox "); got != PublishRunnerSandbox {
		t.Fatalf("NormalizePublishRunner() = %q, want %q", got, PublishRunnerSandbox)
	}
}

func TestValidatePublishRunner(t *testing.T) {
	tests := []struct {
		name    string
		runner  string
		want    string
		wantErr string
	}{
		{name: "host", runner: PublishRunnerHost, want: PublishRunnerHost},
		{name: "sandbox", runner: " Sandbox ", want: PublishRunnerSandbox},
		{name: "auto", runner: "AUTO", want: PublishRunnerAuto},
		{name: "empty", wantErr: "factory publish runner is required"},
		{name: "unsupported", runner: "remote", wantErr: `unsupported factory publish runner "remote" (supported: host, sandbox, auto)`},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidatePublishRunner(tt.runner)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("ValidatePublishRunner() error = nil, want %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ValidatePublishRunner() error = %q, want %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidatePublishRunner() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("ValidatePublishRunner() = %q, want %q", got, tt.want)
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

func TestDerivePostRunStateDerivesLegacyPublishArtifact(t *testing.T) {
	completedAt := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	record := RunRecord{
		RunID: "run-legacy-publish-artifact",
		Artifacts: []ArtifactReference{{
			Name:      "publish-outcome",
			Type:      "json",
			CreatedAt: &completedAt,
			Summary: map[string]any{
				"policy":          "pr",
				"branch":          "hal/legacy-publish",
				"pushed":          true,
				"pullRequestUrl":  "https://github.com/jywlabs/hal/pull/42",
				"recoveredBundle": "recovery/run-legacy-publish-artifact",
			},
		}},
	}

	got := DerivePostRunState(record)
	if got == nil || got.Publish == nil {
		t.Fatalf("DerivePostRunState() = %#v, want publish outcome", got)
	}
	publish := got.Publish
	if publish.Status != RunStatusSucceeded {
		t.Fatalf("publish status = %q, want legacy default %q", publish.Status, RunStatusSucceeded)
	}
	if publish.Policy != "pr" || publish.BranchName != "hal/legacy-publish" || !publish.Pushed {
		t.Fatalf("publish outcome = %#v, want legacy policy/branch/pushed", publish)
	}
	if publish.PullRequestURL != "https://github.com/jywlabs/hal/pull/42" {
		t.Fatalf("pullRequestUrl = %q", publish.PullRequestURL)
	}
	if publish.RecoveredBundle != "recovery/run-legacy-publish-artifact" {
		t.Fatalf("recoveredBundle = %q", publish.RecoveredBundle)
	}
	if publish.Source != "artifact" {
		t.Fatalf("source = %q, want artifact", publish.Source)
	}
	if publish.CompletedAt == nil || !publish.CompletedAt.Equal(completedAt) {
		t.Fatalf("completedAt = %#v, want %s", publish.CompletedAt, completedAt)
	}
	if got.Recovery == nil || got.Recovery.RecoveredBundle != publish.RecoveredBundle {
		t.Fatalf("derived recovery = %#v, want recovery from recovered bundle", got.Recovery)
	}
}

func TestDerivePostRunStateDerivesSandboxPublishArtifactMetadata(t *testing.T) {
	startedAt := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	attemptCompletedAt := startedAt.Add(30 * time.Second)
	completedAt := startedAt.Add(time.Minute)
	record := RunRecord{
		RunID: "run-sandbox-publish-artifact",
		Artifacts: []ArtifactReference{{
			Name:      "publish-outcome",
			Type:      "json",
			CreatedAt: &completedAt,
			Summary: map[string]any{
				"outcomeKind":    "publish",
				"status":         RunStatusSucceeded,
				"policy":         "pr",
				"branchName":     "hal/sandbox-publish",
				"pushed":         true,
				"pullRequestUrl": "https://github.com/jywlabs/hal/pull/77",
				"pullRequestId":  77,
				"runner":         " SANDBOX ",
				"fallbackFrom":   " HOST ",
				"credentialMode": "env",
				"commit":         "abc123def456",
				"attempts": []any{
					map[string]any{
						"runner":      " sandbox ",
						"status":      RunStatusFailed,
						"error":       "sandbox publish failed",
						"startedAt":   startedAt.Format(time.RFC3339Nano),
						"completedAt": attemptCompletedAt.Format(time.RFC3339Nano),
					},
					map[string]any{
						"runner":      PublishRunnerHost,
						"status":      RunStatusSucceeded,
						"startedAt":   attemptCompletedAt,
						"completedAt": completedAt,
					},
				},
			},
		}},
	}

	got := DerivePostRunState(record)
	if got == nil || got.Publish == nil {
		t.Fatalf("DerivePostRunState() = %#v, want publish outcome", got)
	}
	publish := got.Publish
	if publish.Runner != PublishRunnerSandbox {
		t.Fatalf("runner = %q, want %q", publish.Runner, PublishRunnerSandbox)
	}
	if publish.FallbackFrom != PublishRunnerHost {
		t.Fatalf("fallbackFrom = %q, want %q", publish.FallbackFrom, PublishRunnerHost)
	}
	if publish.CredentialMode != "env" || publish.Commit != "abc123def456" {
		t.Fatalf("publish credential/commit metadata = %#v", publish)
	}
	if publish.BranchName != "hal/sandbox-publish" || publish.PullRequestID != 77 {
		t.Fatalf("publish branch/pr metadata = %#v", publish)
	}
	if len(publish.Attempts) != 2 {
		t.Fatalf("attempts len = %d, want 2: %#v", len(publish.Attempts), publish.Attempts)
	}
	firstAttempt := publish.Attempts[0]
	if firstAttempt.Runner != PublishRunnerSandbox || firstAttempt.Status != RunStatusFailed || firstAttempt.Error != "sandbox publish failed" {
		t.Fatalf("first attempt = %#v", firstAttempt)
	}
	if firstAttempt.StartedAt == nil || !firstAttempt.StartedAt.Equal(startedAt) {
		t.Fatalf("first startedAt = %#v, want %s", firstAttempt.StartedAt, startedAt)
	}
	if firstAttempt.CompletedAt == nil || !firstAttempt.CompletedAt.Equal(attemptCompletedAt) {
		t.Fatalf("first completedAt = %#v, want %s", firstAttempt.CompletedAt, attemptCompletedAt)
	}
	secondAttempt := publish.Attempts[1]
	if secondAttempt.Runner != PublishRunnerHost || secondAttempt.Status != RunStatusSucceeded {
		t.Fatalf("second attempt = %#v", secondAttempt)
	}
}

func TestDerivePostRunStatePrefersExplicitPublishOutcome(t *testing.T) {
	startedAt := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	record := RunRecord{
		RunID: "run-explicit-publish",
		PostRun: &PostRunState{Publish: &PublishOutcome{
			Status: RunStatusSucceeded,
			Runner: PublishRunnerHost,
			Attempts: []PublishAttempt{{
				Runner:    PublishRunnerHost,
				Status:    RunStatusSucceeded,
				StartedAt: &startedAt,
			}},
		}},
		Artifacts: []ArtifactReference{{
			Name: "publish-outcome",
			Type: "json",
			Summary: map[string]any{
				"outcomeKind": "publish",
				"runner":      PublishRunnerSandbox,
			},
		}},
	}

	got := DerivePostRunState(record)
	if got == nil || got.Publish == nil {
		t.Fatalf("DerivePostRunState() = %#v, want explicit publish outcome", got)
	}
	if got.Publish.Runner != PublishRunnerHost {
		t.Fatalf("runner = %q, want explicit %q", got.Publish.Runner, PublishRunnerHost)
	}
	if len(got.Publish.Attempts) != 1 || got.Publish.Attempts[0].Runner != PublishRunnerHost {
		t.Fatalf("attempts = %#v, want explicit attempts", got.Publish.Attempts)
	}
	record.PostRun.Publish.Attempts[0].Runner = PublishRunnerSandbox
	if got.Publish.Attempts[0].Runner != PublishRunnerHost {
		t.Fatalf("derived attempts aliased source record: %#v", got.Publish.Attempts)
	}
}

func TestFactoryTypesHaveJSONTags(t *testing.T) {
	types := []reflect.Type{
		reflect.TypeOf(RunRecord{}),
		reflect.TypeOf(PostRunState{}),
		reflect.TypeOf(RecoveryOutcome{}),
		reflect.TypeOf(PublishOutcome{}),
		reflect.TypeOf(PublishAttempt{}),
		reflect.TypeOf(RunSecretInput{}),
		reflect.TypeOf(RunSecretMetadata{}),
		reflect.TypeOf(SandboxHostMetadata{}),
		reflect.TypeOf(SandboxRuntimeMetadata{}),
		reflect.TypeOf(SandboxWorkspaceMetadata{}),
		reflect.TypeOf(SandboxSecurityMetadata{}),
		reflect.TypeOf(SandboxNetworkSecurityMetadata{}),
		reflect.TypeOf(SandboxSecretSecurityMetadata{}),
		reflect.TypeOf(SandboxLeaseMetadata{}),
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

func TestPublishOutcomeJSONFields(t *testing.T) {
	startedAt := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	completedAt := startedAt.Add(time.Minute)
	original := PublishOutcome{
		Status:          RunStatusSucceeded,
		Policy:          "pr",
		BranchName:      "hal/sandbox-publish",
		RecoveredBundle: "recovery/run-sandbox-publish",
		Pushed:          true,
		PullRequestURL:  "https://github.com/jywlabs/hal/pull/42",
		PullRequestID:   42,
		AllowUnverified: true,
		Runner:          PublishRunnerSandbox,
		FallbackFrom:    PublishRunnerHost,
		CredentialMode:  "env",
		Commit:          "abc123def456",
		Attempts: []PublishAttempt{{
			Runner:      PublishRunnerSandbox,
			Status:      RunStatusFailed,
			Error:       "sandbox publish failed",
			StartedAt:   &startedAt,
			CompletedAt: &completedAt,
		}},
		Source:      "artifact",
		CompletedAt: &completedAt,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	raw := mustJSONMapFromBytes(t, data)
	requireExactJSONKeys(t, raw, []string{
		"status",
		"policy",
		"branchName",
		"recoveredBundle",
		"pushed",
		"pullRequestUrl",
		"pullRequestId",
		"allowUnverified",
		"runner",
		"fallbackFrom",
		"credentialMode",
		"commit",
		"attempts",
		"source",
		"completedAt",
	})
	attempt := firstJSONMapArrayObjectMust(t, raw, "attempts")
	requireExactJSONKeys(t, attempt, []string{"runner", "status", "error", "startedAt", "completedAt"})

	var decoded PublishOutcome
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(round-trip) error = %v", err)
	}
	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("round-trip mismatch\n got: %#v\nwant: %#v", decoded, original)
	}
}

func TestPublishOutcomeOptionalFieldsOmitted(t *testing.T) {
	data, err := json.Marshal(PublishOutcome{})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	requireExactJSONKeys(t, mustJSONMapFromBytes(t, data), nil)
}

func TestSandboxHostRuntimeWorkspaceMetadataJSONTags(t *testing.T) {
	tests := []struct {
		name      string
		value     any
		wantKeys  []string
		wantValue map[string]any
		forbidden []string
	}{
		{
			name: "host",
			value: SandboxHostMetadata{
				ID:   "host-123",
				Name: "builder-a",
				Kind: "worker",
			},
			wantKeys: []string{"id", "name", "kind"},
			wantValue: map[string]any{
				"id":   "host-123",
				"name": "builder-a",
				"kind": "worker",
			},
		},
		{
			name: "runtime",
			value: SandboxRuntimeMetadata{
				Driver:         "rootless_podman",
				IsolationLevel: "container",
				RuntimeID:      "runtime-abc",
				Image:          "ghcr.io/jywlabs/hal-worker:2026-06-29",
				WorkerID:       "worker-7",
			},
			wantKeys: []string{"driver", "isolationLevel", "runtimeId", "image", "workerId"},
			wantValue: map[string]any{
				"driver":         "rootless_podman",
				"isolationLevel": "container",
				"runtimeId":      "runtime-abc",
				"image":          "ghcr.io/jywlabs/hal-worker:2026-06-29",
				"workerId":       "worker-7",
			},
		},
		{
			name: "workspace",
			value: SandboxWorkspaceMetadata{
				Mode:        "clone",
				InputSource: "remote_ref",
				Branch:      "hal/factory-runtime-v2",
				SyncRef:     "refs/heads/hal/factory-runtime-v2",
			},
			wantKeys: []string{"mode", "inputSource", "branch", "syncRef"},
			wantValue: map[string]any{
				"mode":        "clone",
				"inputSource": "remote_ref",
				"branch":      "hal/factory-runtime-v2",
				"syncRef":     "refs/heads/hal/factory-runtime-v2",
			},
			forbidden: []string{"repo", "path", "workspacePath", "workspaceRoot", "sourcePath", "storedPath"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.value)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}

			var raw map[string]any
			if err := json.Unmarshal(data, &raw); err != nil {
				t.Fatalf("json.Unmarshal(payload) error = %v", err)
			}

			requireExactJSONKeys(t, raw, tt.wantKeys)
			for key, want := range tt.wantValue {
				if raw[key] != want {
					t.Errorf("%s = %#v, want %#v", key, raw[key], want)
				}
			}
			for _, key := range tt.forbidden {
				if _, ok := raw[key]; ok {
					t.Errorf("unsafe workspace metadata field %q should not be serialized", key)
				}
			}
		})
	}
}

func TestSandboxSecurityLeaseMetadataJSONTags(t *testing.T) {
	security := SandboxSecurityMetadata{
		Network: &SandboxNetworkSecurityMetadata{
			PolicyRequested: "deny_by_default",
			PolicyEnforced:  "best_effort",
			EnforcementMode: "proxy_firewall",
		},
		Secrets: &SandboxSecretSecurityMetadata{
			RequestedModes: []string{"env", "file_tmpfs"},
			ActiveModes:    []string{"file_tmpfs"},
		},
	}

	data, err := json.Marshal(security)
	if err != nil {
		t.Fatalf("json.Marshal(security) error = %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(security payload) error = %v", err)
	}

	requireExactJSONKeys(t, raw, []string{"network", "secrets"})
	requireJSONKeysAbsent(t, raw, []string{
		"secretName",
		"secretNames",
		"secretValue",
		"secretValues",
		"privateKey",
		"token",
		"tokens",
		"rawEnv",
		"environment",
		"credentials",
		"providerCredentials",
	})

	network, ok := raw["network"].(map[string]any)
	if !ok {
		t.Fatalf("network should be an object, got %T", raw["network"])
	}
	requireExactJSONKeys(t, network, []string{"policyRequested", "policyEnforced", "enforcementMode"})
	if network["policyRequested"] != "deny_by_default" {
		t.Errorf("network.policyRequested = %#v, want deny_by_default", network["policyRequested"])
	}
	if network["policyEnforced"] != "best_effort" {
		t.Errorf("network.policyEnforced = %#v, want best_effort", network["policyEnforced"])
	}
	if network["enforcementMode"] != "proxy_firewall" {
		t.Errorf("network.enforcementMode = %#v, want proxy_firewall", network["enforcementMode"])
	}

	secrets, ok := raw["secrets"].(map[string]any)
	if !ok {
		t.Fatalf("secrets should be an object, got %T", raw["secrets"])
	}
	requireExactJSONKeys(t, secrets, []string{"requestedModes", "activeModes"})
	if !reflect.DeepEqual(secrets["requestedModes"], []any{"env", "file_tmpfs"}) {
		t.Errorf("secrets.requestedModes = %#v, want [env file_tmpfs]", secrets["requestedModes"])
	}
	if !reflect.DeepEqual(secrets["activeModes"], []any{"file_tmpfs"}) {
		t.Errorf("secrets.activeModes = %#v, want [file_tmpfs]", secrets["activeModes"])
	}

	expiresAt := time.Date(2026, 6, 29, 14, 30, 0, 0, time.UTC)
	acquiredAt := expiresAt.Add(-30 * time.Minute)
	lease := SandboxLeaseMetadata{
		ID:            "lease-123",
		HostID:        "host-123",
		HostName:      "worker-a",
		RuntimeDriver: "rootless_podman",
		ResourceKey:   "host:worker-a",
		Purpose:       "factory",
		RunID:         "run-456",
		AcquiredAt:    acquiredAt,
		ExpiresAt:     expiresAt,
	}

	data, err = json.Marshal(lease)
	if err != nil {
		t.Fatalf("json.Marshal(lease) error = %v", err)
	}

	raw = map[string]any{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(lease payload) error = %v", err)
	}

	requireExactJSONKeys(t, raw, []string{
		"id", "hostId", "hostName", "runtimeDriver", "resourceKey", "purpose",
		"runId", "acquiredAt", "expiresAt",
	})
	if raw["id"] != "lease-123" {
		t.Errorf("lease.id = %#v, want lease-123", raw["id"])
	}
	if raw["hostId"] != "host-123" {
		t.Errorf("lease.hostId = %#v, want host-123", raw["hostId"])
	}
	if raw["hostName"] != "worker-a" {
		t.Errorf("lease.hostName = %#v, want worker-a", raw["hostName"])
	}
	if raw["runtimeDriver"] != "rootless_podman" {
		t.Errorf("lease.runtimeDriver = %#v, want rootless_podman", raw["runtimeDriver"])
	}
	if raw["resourceKey"] != "host:worker-a" {
		t.Errorf("lease.resourceKey = %#v, want host:worker-a", raw["resourceKey"])
	}
	if raw["purpose"] != "factory" {
		t.Errorf("lease.purpose = %#v, want factory", raw["purpose"])
	}
	if raw["runId"] != "run-456" {
		t.Errorf("lease.runId = %#v, want run-456", raw["runId"])
	}
	if raw["acquiredAt"] != acquiredAt.Format(time.RFC3339) {
		t.Errorf("lease.acquiredAt = %#v, want %q", raw["acquiredAt"], acquiredAt.Format(time.RFC3339))
	}
	if raw["expiresAt"] != expiresAt.Format(time.RFC3339) {
		t.Errorf("lease.expiresAt = %#v, want %q", raw["expiresAt"], expiresAt.Format(time.RFC3339))
	}
	if _, ok := raw["holder"]; ok {
		t.Fatal("lease holder must not be serialized")
	}
}

func TestSandboxSecurityCapabilityReadinessMetadataJSONTags(t *testing.T) {
	security := SandboxSecurityMetadata{
		CapabilityReadiness: testFactorySandboxCapabilityReadinessOutput(),
	}

	data, err := json.Marshal(security)
	if err != nil {
		t.Fatalf("json.Marshal(security) error = %v", err)
	}

	raw := mustJSONMapFromBytes(t, data)
	requireExactJSONKeys(t, raw, []string{"capabilityReadiness"})
	requireJSONKeysAbsent(t, raw, []string{"network", "secrets"})

	readiness, ok := raw["capabilityReadiness"].(map[string]any)
	if !ok {
		t.Fatalf("capabilityReadiness should be an object, got %T", raw["capabilityReadiness"])
	}
	requireExactJSONKeys(t, readiness, []string{"results"})

	results, ok := readiness["results"].([]any)
	if !ok || len(results) != 1 {
		t.Fatalf("capabilityReadiness.results = %#v, want one result", readiness["results"])
	}
	result, ok := results[0].(map[string]any)
	if !ok {
		t.Fatalf("capabilityReadiness result should be an object, got %T", results[0])
	}
	if result["state"] != string(sandbox.SandboxSecurityCapabilityReadinessReady) {
		t.Fatalf("capabilityReadiness result state = %#v", result["state"])
	}
}

func TestSandboxSecurityCapabilityReadinessDiagnosticsMetadataJSONTags(t *testing.T) {
	readiness := testFactorySandboxCapabilityReadinessOutput()
	diagnostics := sandbox.DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(*readiness)
	security := SandboxSecurityMetadata{
		CapabilityReadiness:            readiness,
		CapabilityReadinessDiagnostics: &diagnostics,
	}

	data, err := json.Marshal(security)
	if err != nil {
		t.Fatalf("json.Marshal(security) error = %v", err)
	}

	raw := mustJSONMapFromBytes(t, data)
	requireExactJSONKeys(t, raw, []string{"capabilityReadiness", "capabilityReadinessDiagnostics"})

	diagnosticsJSON, ok := raw["capabilityReadinessDiagnostics"].(map[string]any)
	if !ok {
		t.Fatalf("capabilityReadinessDiagnostics should be an object, got %T", raw["capabilityReadinessDiagnostics"])
	}
	requireExactJSONKeys(t, diagnosticsJSON, []string{"status", "total", "highestSeverity", "advisoryOnly", "wouldBlockStrictGate", "items"})
	if diagnosticsJSON["status"] != string(sandbox.SandboxSecurityCapabilityDiagnosticSummaryStatusReady) {
		t.Fatalf("capabilityReadinessDiagnostics.status = %#v, want ready", diagnosticsJSON["status"])
	}
}

func TestSandboxMetadataLoadsLegacyJSON(t *testing.T) {
	payload := []byte(`{
		"name": "factory-run",
		"provider": "daytona",
		"size": "medium",
		"status": "running",
		"connection": {
			"address": "100.64.0.10",
			"publicIp": "203.0.113.10",
			"tailscaleIp": "100.64.0.10",
			"tailscaleHostname": "factory-run.tailnet.ts.net",
			"tailscaleLockdown": true
		},
		"sshCommand": "hal sandbox ssh factory-run",
		"cleanupCommand": "hal sandbox delete factory-run",
		"handoff": "Inspect the sandbox before cleanup."
	}`)

	var decoded SandboxMetadata
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(legacy sandbox metadata) error = %v", err)
	}

	if decoded.Name != "factory-run" {
		t.Fatalf("name = %q, want factory-run", decoded.Name)
	}
	if decoded.Provider != "daytona" {
		t.Fatalf("provider = %q, want daytona", decoded.Provider)
	}
	if decoded.Connection == nil || !decoded.Connection.TailscaleLockdown {
		t.Fatalf("connection = %#v, want populated lockdown metadata", decoded.Connection)
	}
	if decoded.Host != nil {
		t.Fatalf("host = %#v, want nil for omitted legacy field", decoded.Host)
	}
	if decoded.Runtime != nil {
		t.Fatalf("runtime = %#v, want nil for omitted legacy field", decoded.Runtime)
	}
	if decoded.Workspace != nil {
		t.Fatalf("workspace = %#v, want nil for omitted legacy field", decoded.Workspace)
	}
	if decoded.Security != nil {
		t.Fatalf("security = %#v, want nil for omitted legacy field", decoded.Security)
	}
	if decoded.CredentialProxyPlan != nil {
		t.Fatalf("credentialProxyPlan = %#v, want nil for omitted legacy field", decoded.CredentialProxyPlan)
	}
	if decoded.CredentialProxySession != nil {
		t.Fatalf("credentialProxySession = %#v, want nil for omitted legacy field", decoded.CredentialProxySession)
	}
	if len(decoded.CredentialProxyBindings) != 0 {
		t.Fatalf("credentialProxyBindings = %#v, want empty for omitted legacy field", decoded.CredentialProxyBindings)
	}
	if decoded.Lease != nil {
		t.Fatalf("lease = %#v, want nil for omitted legacy field", decoded.Lease)
	}
	if decoded.WorkerRouting != nil {
		t.Fatalf("workerRouting = %#v, want nil for omitted legacy field", decoded.WorkerRouting)
	}
}

func TestFactoryCredentialProxyLegacyRecordsAndEventsLoadWithoutMetadata(t *testing.T) {
	runPayload := []byte(`{
		"runId": "run-legacy-credential-proxy",
		"status": "running",
		"executorMode": "sandbox",
		"source": {"kind": "prd", "path": ".hal/prd.json"},
		"repoPath": "/repo",
		"repoRemote": "origin",
		"branchName": "hal/legacy-record",
		"baseBranch": "main",
		"sandboxName": "factory-run",
		"sandbox": {
			"name": "factory-run",
			"provider": "daytona",
			"status": "running"
		},
		"currentStep": "run",
		"createdAt": "2026-07-02T10:00:00Z",
		"updatedAt": "2026-07-02T10:00:00Z"
	}`)

	var record RunRecord
	if err := json.Unmarshal(runPayload, &record); err != nil {
		t.Fatalf("json.Unmarshal(legacy run record) error = %v", err)
	}
	if record.Sandbox == nil {
		t.Fatal("sandbox metadata = nil, want decoded legacy sandbox metadata")
	}
	if record.Sandbox.CredentialProxyPlan != nil {
		t.Fatalf("CredentialProxyPlan = %#v, want nil for legacy record", record.Sandbox.CredentialProxyPlan)
	}
	if record.Sandbox.CredentialProxySession != nil {
		t.Fatalf("CredentialProxySession = %#v, want nil for legacy record", record.Sandbox.CredentialProxySession)
	}
	if len(record.Sandbox.CredentialProxyBindings) != 0 {
		t.Fatalf("CredentialProxyBindings = %#v, want empty for legacy record", record.Sandbox.CredentialProxyBindings)
	}
	recordData, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("json.Marshal(legacy run record) error = %v", err)
	}
	requireJSONKeysAbsent(t, mustJSONMapFromBytes(t, recordData), []string{
		"credentialProxy", "credentialProxyPlan", "credentialProxySession", "credentialProxyBindings",
	})

	eventPayload := []byte(`{
		"sequence": 1,
		"runId": "run-legacy-credential-proxy",
		"eventType": "run_created",
		"timestamp": "2026-07-02T10:00:00Z",
		"message": "factory run created"
	}`)
	var event EventRecord
	if err := json.Unmarshal(eventPayload, &event); err != nil {
		t.Fatalf("json.Unmarshal(legacy event record) error = %v", err)
	}
	eventData, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal(legacy event record) error = %v", err)
	}
	requireJSONKeysAbsent(t, mustJSONMapFromBytes(t, eventData), []string{
		"credentialProxy", "credentialProxyPlan", "credentialProxySession", "credentialProxyBindings",
	})
}

func TestSandboxMetadataOptionalMetadataOmittedWhenNil(t *testing.T) {
	metadata := SandboxMetadata{
		Name:           "factory-run",
		Provider:       "daytona",
		Status:         "running",
		SSHCommand:     "hal sandbox ssh factory-run",
		CleanupCommand: "hal sandbox delete factory-run",
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("json.Marshal(sandbox metadata) error = %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(sandbox metadata payload) error = %v", err)
	}

	requireExactJSONKeys(t, raw, []string{"name", "provider", "status", "sshCommand", "cleanupCommand"})
	requireJSONKeysAbsent(t, raw, []string{
		"networkProxySession", "networkPolicyDecisionLog", "networkPolicyDecisionLogs",
		"credentialProxy", "credentialProxyPlan", "credentialProxySession", "credentialProxyBindings",
	})
}

func TestSandboxMetadataNetworkProxySessionJSONShape(t *testing.T) {
	session := sandbox.SanitizeSandboxNetworkProxySessionMetadata(sandbox.SandboxNetworkProxySessionMetadata{
		ID:     " proxy-session-01 ",
		Source: sandbox.SandboxNetworkPolicyDecisionSource(" FACTORY "),
		PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
			ID:        " policy-snapshot-01 ",
			Version:   " policy-v1 ",
			Preset:    sandbox.SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
			RuleSetID: " rules-01 ",
		},
		EnforcementMode: " PROXY ",
	})
	metadata := SandboxMetadata{
		Name:                "factory-run",
		Provider:            "daytona",
		Status:              "running",
		NetworkProxySession: &session,
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("json.Marshal(sandbox metadata) error = %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(sandbox metadata payload) error = %v", err)
	}

	requireExactJSONKeys(t, raw, []string{"name", "provider", "status", "networkProxySession"})
	requireJSONKeysAbsent(t, raw, []string{"networkPolicyDecisionLog", "networkPolicyDecisionLogs"})

	proxySession, ok := raw["networkProxySession"].(map[string]any)
	if !ok {
		t.Fatalf("networkProxySession should be an object, got %T", raw["networkProxySession"])
	}
	requireExactJSONKeys(t, proxySession, []string{"id", "source", "policySnapshot", "enforcementMode"})
	if proxySession["id"] != "proxy-session-01" {
		t.Fatalf("networkProxySession.id = %#v, want proxy-session-01", proxySession["id"])
	}
	if proxySession["source"] != string(sandbox.SandboxNetworkPolicyDecisionSourceFactory) {
		t.Fatalf("networkProxySession.source = %#v, want factory", proxySession["source"])
	}
	if proxySession["enforcementMode"] != sandbox.SandboxNetworkEnforcementModeProxy {
		t.Fatalf("networkProxySession.enforcementMode = %#v, want proxy", proxySession["enforcementMode"])
	}

	snapshot, ok := proxySession["policySnapshot"].(map[string]any)
	if !ok {
		t.Fatalf("networkProxySession.policySnapshot should be an object, got %T", proxySession["policySnapshot"])
	}
	requireExactJSONKeys(t, snapshot, []string{"id", "version", "preset", "ruleSetId"})
	if snapshot["id"] != "policy-snapshot-01" || snapshot["version"] != "policy-v1" || snapshot["ruleSetId"] != "rules-01" {
		t.Fatalf("policySnapshot = %#v, want safe snapshot identifiers preserved", snapshot)
	}
	if snapshot["preset"] != string(sandbox.SandboxNetworkPolicyPresetDenyByDefault) {
		t.Fatalf("policySnapshot.preset = %#v, want deny_by_default", snapshot["preset"])
	}
}

func TestSandboxMetadataCredentialProxyMetadataTypesAndJSONShape(t *testing.T) {
	metadataType := reflect.TypeOf(SandboxMetadata{})
	for _, field := range []struct {
		name string
		typ  reflect.Type
	}{
		{name: "CredentialProxyPlan", typ: reflect.TypeOf((*sandbox.SandboxCredentialProxyPlanMetadata)(nil))},
		{name: "CredentialProxySession", typ: reflect.TypeOf((*sandbox.SandboxCredentialProxySessionMetadata)(nil))},
		{name: "CredentialProxyBindings", typ: reflect.TypeOf([]sandbox.SandboxCredentialProxyBindingMetadata(nil))},
		{name: "CredentialDelivery", typ: reflect.TypeOf((*sandbox.SandboxCredentialDeliveryStatusMetadata)(nil))},
	} {
		got, ok := metadataType.FieldByName(field.name)
		if !ok {
			t.Fatalf("SandboxMetadata missing field %s", field.name)
		}
		if got.Type != field.typ {
			t.Fatalf("SandboxMetadata.%s type = %s, want %s", field.name, got.Type, field.typ)
		}
		if got.Tag.Get("json") == "" || !strings.Contains(","+got.Tag.Get("json")+",", ",omitempty,") {
			t.Fatalf("SandboxMetadata.%s json tag = %q, want omitempty", field.name, got.Tag.Get("json"))
		}
	}

	plan := sandbox.SanitizeSandboxCredentialProxyPlanMetadata(sandbox.SandboxCredentialProxyPlanMetadata{
		ID:                    " credential-plan-01 ",
		Source:                sandbox.SandboxCredentialProxySource(" FACTORY "),
		SecretBrokerSessionID: " secret-session-01 ",
		NetworkProxySessionID: " proxy-session-01 ",
		PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
			ID:     " policy-snapshot-01 ",
			Preset: sandbox.SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
		},
		BindingCount: 1,
		Mode:         sandbox.SandboxCredentialProxyMode(" BROKERED_NETWORK_REFERENCE "),
		Status:       sandbox.SandboxCredentialProxyStatus(" PLANNED "),
	})
	session := sandbox.SanitizeSandboxCredentialProxySessionMetadata(sandbox.SandboxCredentialProxySessionMetadata{
		ID:                    " credential-session-01 ",
		PlanID:                " credential-plan-01 ",
		Source:                sandbox.SandboxCredentialProxySource(" FACTORY "),
		SecretBrokerSessionID: " secret-session-01 ",
		NetworkProxySessionID: " proxy-session-01 ",
		PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
			ID:     " policy-snapshot-01 ",
			Preset: sandbox.SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
		},
		Status:      sandbox.SandboxCredentialProxyStatus(" ACTIVE "),
		WarningCode: sandbox.SandboxCredentialProxyWarningCode(" BINDING_OMITTED "),
		ReasonCode:  sandbox.SandboxCredentialProxyReasonCode(" REQUESTED "),
	})
	binding := sandbox.SanitizeSandboxCredentialProxyBindingMetadata(sandbox.SandboxCredentialProxyBindingMetadata{
		ID:                  " credential-binding-01 ",
		PlanID:              " credential-plan-01 ",
		SessionID:           " credential-session-01 ",
		SecretID:            "env:GITHUB_TOKEN",
		DeliveryMode:        sandbox.SandboxCredentialProxyDeliveryMode(" HTTP_PROXY "),
		RequestCategory:     sandbox.SandboxCredentialProxyRequestCategory(" NETWORK_AUTH "),
		DestinationCategory: sandbox.SandboxNetworkPolicyDestinationCategory(" PUBLIC_INTERNET "),
		Outcome:             sandbox.SandboxCredentialProxyBindingOutcome(" BOUND "),
		Status:              sandbox.SandboxCredentialProxyStatus(" ACTIVE "),
		ReasonCode:          sandbox.SandboxCredentialProxyReasonCode(" REQUESTED "),
	})
	metadata := SandboxMetadata{
		Name:                    "factory-run",
		Provider:                "daytona",
		Status:                  "running",
		CredentialProxyPlan:     &plan,
		CredentialProxySession:  &session,
		CredentialProxyBindings: []sandbox.SandboxCredentialProxyBindingMetadata{binding},
		CredentialDelivery: &sandbox.SandboxCredentialDeliveryStatusMetadata{
			ID:             "credential-plan-01",
			PlanID:         "credential-plan-01",
			RequestedModes: []string{sandbox.SandboxSecretModeHTTPProxy},
			Status:         "planned",
		},
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("json.Marshal(sandbox metadata) error = %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(sandbox metadata payload) error = %v", err)
	}
	requireExactJSONKeys(t, raw, []string{
		"name", "provider", "status",
		"credentialProxyPlan", "credentialProxySession", "credentialProxyBindings", "credentialDelivery",
	})
	requireJSONKeysAbsent(t, raw, []string{"credentialProxy"})

	credentialProxyPlan, ok := raw["credentialProxyPlan"].(map[string]any)
	if !ok {
		t.Fatalf("credentialProxyPlan should be an object, got %T", raw["credentialProxyPlan"])
	}
	requireExactJSONKeys(t, credentialProxyPlan, []string{
		"id", "source", "secretBrokerSessionId", "networkProxySessionId",
		"policySnapshot", "bindingCount", "mode", "status",
	})
	if credentialProxyPlan["source"] != string(sandbox.SandboxCredentialProxySourceFactory) {
		t.Fatalf("credentialProxyPlan.source = %#v, want factory", credentialProxyPlan["source"])
	}
	if credentialProxyPlan["mode"] != string(sandbox.SandboxCredentialProxyModeBrokeredNetworkReference) {
		t.Fatalf("credentialProxyPlan.mode = %#v, want brokered_network_reference", credentialProxyPlan["mode"])
	}

	credentialProxySession, ok := raw["credentialProxySession"].(map[string]any)
	if !ok {
		t.Fatalf("credentialProxySession should be an object, got %T", raw["credentialProxySession"])
	}
	requireExactJSONKeys(t, credentialProxySession, []string{
		"id", "planId", "source", "secretBrokerSessionId", "networkProxySessionId",
		"policySnapshot", "status", "warningCode", "reasonCode",
	})
	if credentialProxySession["status"] != string(sandbox.SandboxCredentialProxyStatusActive) {
		t.Fatalf("credentialProxySession.status = %#v, want active", credentialProxySession["status"])
	}

	credentialProxyBinding, ok := firstJSONMapArrayObject(t, raw, "credentialProxyBindings")
	if !ok {
		t.Fatalf("credentialProxyBindings[0] should be an object, got %#v", raw["credentialProxyBindings"])
	}
	requireExactJSONKeys(t, credentialProxyBinding, []string{
		"id", "planId", "sessionId", "secretId", "deliveryMode", "requestCategory",
		"destinationCategory", "outcome", "status", "reasonCode",
	})
	if credentialProxyBinding["secretId"] != "env:GITHUB_TOKEN" {
		t.Fatalf("credentialProxyBindings[0].secretId = %#v, want env:GITHUB_TOKEN", credentialProxyBinding["secretId"])
	}
	if credentialProxyBinding["deliveryMode"] != string(sandbox.SandboxCredentialProxyDeliveryModeHTTPProxy) {
		t.Fatalf("credentialProxyBindings[0].deliveryMode = %#v, want http_proxy", credentialProxyBinding["deliveryMode"])
	}
}

func TestSandboxMetadataNetworkProxySessionJSONRedactionSafety(t *testing.T) {
	for _, sensitive := range networkProxyRedactionTestValues() {
		t.Run(sensitive, func(t *testing.T) {
			session := sandbox.SanitizeSandboxNetworkProxySessionMetadata(sandbox.SandboxNetworkProxySessionMetadata{
				ID:     sensitive,
				Source: sandbox.SandboxNetworkPolicyDecisionSource(" FACTORY "),
				PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
					ID:        " policy-snapshot-01 ",
					Version:   sensitive,
					Preset:    sandbox.SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
					RuleSetID: sensitive,
				},
				EnforcementMode: sensitive,
			})
			metadata := SandboxMetadata{
				Name:                "factory-run",
				Provider:            "daytona",
				Status:              "running",
				NetworkProxySession: &session,
			}

			data, err := json.Marshal(metadata)
			if err != nil {
				t.Fatalf("json.Marshal(sandbox metadata) error = %v", err)
			}
			encoded := string(data)
			if strings.Contains(encoded, sensitive) {
				t.Fatalf("sandbox metadata leaked unsafe proxy session value %q: %s", sensitive, encoded)
			}
			for _, want := range []string{
				"networkProxySession",
				"policy-snapshot-01",
				string(sandbox.SandboxNetworkPolicyDecisionSourceFactory),
				string(sandbox.SandboxNetworkPolicyPresetDenyByDefault),
			} {
				if !strings.Contains(encoded, want) {
					t.Fatalf("sandbox metadata omitted safe value %q after sanitization: %s", want, encoded)
				}
			}
		})
	}
}

func TestSandboxMetadataRuntimeV2SummaryJSONShape(t *testing.T) {
	expiresAt := time.Date(2026, 6, 29, 16, 45, 0, 0, time.UTC)
	metadata := SandboxMetadata{
		Name:     "factory-run",
		Provider: "daytona",
		Size:     "medium",
		Status:   "running",
		Connection: &SandboxConnectionMetadata{
			TailscaleLockdown: true,
		},
		SSHCommand:     "hal sandbox ssh factory-run",
		CleanupCommand: "hal sandbox delete factory-run",
		Handoff:        "Inspect the sandbox before cleanup.",
		Host: &SandboxHostMetadata{
			ID:   "host-123",
			Name: "worker-a",
			Kind: "worker",
		},
		Runtime: &SandboxRuntimeMetadata{
			Driver:         "rootless_podman",
			IsolationLevel: "container",
			RuntimeID:      "runtime-abc",
			Image:          "ghcr.io/jywlabs/hal-worker:2026-06-29",
			WorkerID:       "worker-7",
		},
		Workspace: &SandboxWorkspaceMetadata{
			Mode:        "clone",
			InputSource: "remote_ref",
			Branch:      "hal/factory-runtime-v2",
			SyncRef:     "refs/heads/hal/factory-runtime-v2",
		},
		Security: &SandboxSecurityMetadata{
			Network: &SandboxNetworkSecurityMetadata{
				PolicyRequested: "deny_by_default",
				PolicyEnforced:  "best_effort",
				EnforcementMode: "proxy_firewall",
			},
			Secrets: &SandboxSecretSecurityMetadata{
				RequestedModes: []string{"env", "file_tmpfs"},
				ActiveModes:    []string{"file_tmpfs"},
			},
		},
		Lease: &SandboxLeaseMetadata{
			ID:            "lease-123",
			HostID:        "host-123",
			HostName:      "worker-a",
			RuntimeDriver: "rootless_podman",
			ResourceKey:   "host:worker-a",
			Purpose:       "factory",
			RunID:         "run-456",
			AcquiredAt:    expiresAt.Add(-30 * time.Minute),
			ExpiresAt:     expiresAt,
		},
		WorkerRouting: &sandbox.WorkerRoutingMetadata{
			SelectedWorkerHostID:   "host-123",
			SelectedWorkerHostName: "worker-a",
			RuntimeDriverID:        sandbox.SandboxRuntimeDriverRootlessPodman,
			IsolationLevel:         sandbox.SandboxIsolationLevelContainer,
			EndpointSummary:        "local Unix socket",
		},
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("json.Marshal(sandbox metadata) error = %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(sandbox metadata payload) error = %v", err)
	}

	requireExactJSONKeys(t, raw, []string{
		"name",
		"provider",
		"size",
		"status",
		"connection",
		"sshCommand",
		"cleanupCommand",
		"handoff",
		"host",
		"runtime",
		"workspace",
		"security",
		"lease",
		"workerRouting",
	})
	requireJSONKeysAbsent(t, raw, []string{
		"path",
		"paths",
		"hostPath",
		"hostPaths",
		"workspacePath",
		"workspaceRoot",
		"sourcePath",
		"storedPath",
		"repo",
		"secretName",
		"secretNames",
		"secretValue",
		"secretValues",
		"privateKey",
		"token",
		"tokens",
		"rawEnv",
		"rawEnvironment",
		"environment",
		"credentials",
		"providerCredentials",
		"holder",
	})

	host, ok := raw["host"].(map[string]any)
	if !ok {
		t.Fatalf("host should be an object, got %T", raw["host"])
	}
	requireExactJSONKeys(t, host, []string{"id", "name", "kind"})

	runtime, ok := raw["runtime"].(map[string]any)
	if !ok {
		t.Fatalf("runtime should be an object, got %T", raw["runtime"])
	}
	requireExactJSONKeys(t, runtime, []string{"driver", "isolationLevel", "runtimeId", "image", "workerId"})

	workspace, ok := raw["workspace"].(map[string]any)
	if !ok {
		t.Fatalf("workspace should be an object, got %T", raw["workspace"])
	}
	requireExactJSONKeys(t, workspace, []string{"mode", "inputSource", "branch", "syncRef"})

	security, ok := raw["security"].(map[string]any)
	if !ok {
		t.Fatalf("security should be an object, got %T", raw["security"])
	}
	requireExactJSONKeys(t, security, []string{"network", "secrets"})

	network, ok := security["network"].(map[string]any)
	if !ok {
		t.Fatalf("security.network should be an object, got %T", security["network"])
	}
	requireExactJSONKeys(t, network, []string{"policyRequested", "policyEnforced", "enforcementMode"})

	secrets, ok := security["secrets"].(map[string]any)
	if !ok {
		t.Fatalf("security.secrets should be an object, got %T", security["secrets"])
	}
	requireExactJSONKeys(t, secrets, []string{"requestedModes", "activeModes"})
	if !reflect.DeepEqual(secrets["requestedModes"], []any{"env", "file_tmpfs"}) {
		t.Errorf("security.secrets.requestedModes = %#v, want [env file_tmpfs]", secrets["requestedModes"])
	}
	if !reflect.DeepEqual(secrets["activeModes"], []any{"file_tmpfs"}) {
		t.Errorf("security.secrets.activeModes = %#v, want [file_tmpfs]", secrets["activeModes"])
	}

	lease, ok := raw["lease"].(map[string]any)
	if !ok {
		t.Fatalf("lease should be an object, got %T", raw["lease"])
	}
	requireExactJSONKeys(t, lease, []string{
		"id", "hostId", "hostName", "runtimeDriver", "resourceKey", "purpose",
		"runId", "acquiredAt", "expiresAt",
	})
	if lease["expiresAt"] != expiresAt.Format(time.RFC3339) {
		t.Errorf("lease.expiresAt = %#v, want %q", lease["expiresAt"], expiresAt.Format(time.RFC3339))
	}

	workerRouting, ok := raw["workerRouting"].(map[string]any)
	if !ok {
		t.Fatalf("workerRouting should be an object, got %T", raw["workerRouting"])
	}
	requireExactJSONKeys(t, workerRouting, []string{
		"selectedWorkerHostId",
		"selectedWorkerHostName",
		"runtimeDriverId",
		"isolationLevel",
		"endpointSummary",
	})
	requireJSONKeysAbsent(t, workerRouting, []string{
		"endpoint",
		"endpointPath",
		"socketPath",
		"hostPath",
		"localPath",
		"remotePath",
		"tempPath",
	})
	if workerRouting["endpointSummary"] != "local Unix socket" {
		t.Fatalf("workerRouting.endpointSummary = %#v, want safe summary", workerRouting["endpointSummary"])
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
			ExactUpstream:      true,
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
	for _, key := range []string{"refreshHal", "installMissingClis", "dryRun", "exactUpstream"} {
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

func mustJSONMapFromBytes(t *testing.T, data []byte) map[string]any {
	t.Helper()

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}
	return raw
}

func testFactorySandboxCapabilityReadinessOutput() *sandbox.SandboxSecurityCapabilityReadinessOutput {
	return &sandbox.SandboxSecurityCapabilityReadinessOutput{
		Results: []sandbox.SandboxSecurityCapabilityReadinessResult{{
			State: sandbox.SandboxSecurityCapabilityReadinessReady,
			Requested: &sandbox.SandboxSecurityCapabilityMetadata{
				ID:         "factory-capability-requested",
				Family:     sandbox.SandboxSecurityCapabilityFamilySecretDelivery,
				Capability: sandbox.SandboxSecurityCapabilitySecretEnv,
				Source:     sandbox.SandboxSecurityCapabilitySourceRequested,
			},
			Ready: &sandbox.SandboxSecurityCapabilityMetadata{
				ID:         "factory-capability-ready",
				Family:     sandbox.SandboxSecurityCapabilityFamilySecretDelivery,
				Capability: sandbox.SandboxSecurityCapabilitySecretEnv,
				Source:     sandbox.SandboxSecurityCapabilitySourceRuntime,
				Status:     sandbox.SandboxSecurityCapabilityReadinessReady,
				ReasonCode: sandbox.SandboxSecurityCapabilityReasonCapabilityConfirmed,
			},
			ReasonCode: sandbox.SandboxSecurityCapabilityReasonCapabilityConfirmed,
		}},
	}
}

func firstJSONMapArrayObject(t *testing.T, values map[string]any, key string) (map[string]any, bool) {
	t.Helper()

	items, ok := values[key].([]any)
	if !ok || len(items) == 0 {
		return nil, false
	}
	first, ok := items[0].(map[string]any)
	return first, ok
}

func firstJSONMapArrayObjectMust(t *testing.T, values map[string]any, key string) map[string]any {
	t.Helper()

	first, ok := firstJSONMapArrayObject(t, values, key)
	if !ok {
		t.Fatalf("%s[0] should be an object, got %#v", key, values[key])
	}
	return first
}

func networkProxyRedactionTestValues() []string {
	return []string{
		"api.example.com",
		"169.254.169.254",
		"https://user:secret@example.test/path?token=secret",
		"unix:///tmp/private/proxy.sock",
		"/Users/alice/project",
		"Authorization",
		"Bearer",
		"OPENAI_API_KEY",
		"raw-header-token-value",
		"raw body secret value",
	}
}

func requireJSONKeysAbsent(t *testing.T, value any, forbidden []string) {
	t.Helper()

	forbiddenSet := map[string]struct{}{}
	for _, key := range forbidden {
		forbiddenSet[key] = struct{}{}
	}

	var walk func(path string, value any)
	walk = func(path string, value any) {
		switch typed := value.(type) {
		case map[string]any:
			for key, nested := range typed {
				nestedPath := key
				if path != "" {
					nestedPath = path + "." + key
				}
				if _, ok := forbiddenSet[key]; ok {
					t.Fatalf("unsafe JSON field %q should not be serialized", nestedPath)
				}
				walk(nestedPath, nested)
			}
		case []any:
			for _, nested := range typed {
				walk(path, nested)
			}
		}
	}

	walk("", value)
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

func TestEventRecordNetworkPolicyDecisionLogsJSONFields(t *testing.T) {
	timestamp := time.Date(2026, 7, 2, 6, 45, 0, 0, time.UTC)
	original := EventRecord{
		Sequence:  8,
		RunID:     "run-network-policy-decision-logs",
		EventType: EventTypePolicyDecision,
		Timestamp: timestamp,
		NetworkPolicyDecisionLogs: sandbox.SanitizeSandboxNetworkPolicyDecisionLogRecords([]sandbox.SandboxNetworkPolicyDecisionLogRecord{{
			ID:             " decision-01 ",
			Source:         sandbox.SandboxNetworkPolicyDecisionSource(" FACTORY "),
			ProxySessionID: " proxy-session-01 ",
			PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
				ID:        " policy-snapshot-01 ",
				Version:   " policy-v1 ",
				Preset:    sandbox.SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
				RuleSetID: " rules-01 ",
			},
			Request: &sandbox.SandboxNetworkPolicyRequestSummary{
				ID:                  " request-01 ",
				Operation:           " connect ",
				DestinationCategory: sandbox.SandboxNetworkPolicyDestinationCategory(" METADATA_SERVICE "),
			},
			Outcome:         sandbox.SandboxNetworkPolicyDecisionOutcome(" DENIED "),
			ReasonCode:      sandbox.SandboxNetworkPolicyDecisionReasonCode(" DEFAULT_DENY "),
			RuleKind:        sandbox.SandboxNetworkPolicyRuleKind(" DOMAIN "),
			PolicyPreset:    sandbox.SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
			EnforcementMode: sandbox.SandboxNetworkEnforcementModeFirewall,
		}}),
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}
	for _, key := range []string{"sequence", "runId", "eventType", "timestamp", "networkPolicyDecisionLogs"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing event JSON field %q", key)
		}
	}

	decisionLogs, ok := raw["networkPolicyDecisionLogs"].([]any)
	if !ok || len(decisionLogs) != 1 {
		t.Fatalf("networkPolicyDecisionLogs = %#v, want one record", raw["networkPolicyDecisionLogs"])
	}
	decisionLog, ok := decisionLogs[0].(map[string]any)
	if !ok {
		t.Fatalf("networkPolicyDecisionLogs[0] should be an object, got %T", decisionLogs[0])
	}
	requireExactJSONKeys(t, decisionLog, []string{
		"id", "source", "proxySessionId", "policySnapshot", "request",
		"outcome", "reasonCode", "ruleKind", "policyPreset", "enforcementMode",
	})
	if decisionLog["source"] != string(sandbox.SandboxNetworkPolicyDecisionSourceFactory) {
		t.Fatalf("decision log source = %#v, want factory", decisionLog["source"])
	}
	if decisionLog["outcome"] != string(sandbox.SandboxNetworkPolicyDecisionOutcomeDenied) {
		t.Fatalf("decision log outcome = %#v, want denied", decisionLog["outcome"])
	}
	if decisionLog["reasonCode"] != string(sandbox.SandboxNetworkPolicyDecisionReasonDefaultDeny) {
		t.Fatalf("decision log reasonCode = %#v, want default_deny", decisionLog["reasonCode"])
	}
	if request, ok := decisionLog["request"].(map[string]any); !ok || request["destinationCategory"] != string(sandbox.SandboxNetworkPolicyDestinationMetadataService) {
		t.Fatalf("decision log request = %#v, want metadata_service destination category", decisionLog["request"])
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

func TestPolicyDecisionMetadataSecurityReadinessGateOptionalFields(t *testing.T) {
	original := PolicyDecisionMetadata{
		PolicyField: "factory.policy.securityReadinessGatePolicyMode",
		Decision:    PolicyDecisionBlockedGate,
		Outcome:     PolicyOutcomeBlocked,
		Reason:      string(sandbox.SandboxSecurityCapabilityReadinessGateReasonCapabilityUnsupported),
		PolicyMode:  sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		Code:        sandbox.SandboxSecurityCapabilityReadinessGateCodeBlocked,
		Counts: &sandbox.SandboxSecurityCapabilityReadinessGateCounts{
			Total:          2,
			Advisory:       2,
			MetadataOnly:   1,
			Unsupported:    1,
			StrictBlocking: 2,
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
	for _, key := range []string{"policyField", "decision", "outcome", "reason", "policyMode", "code", "counts"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing readiness gate policy metadata field %q", key)
		}
	}
	for _, forbidden := range []string{"token", "secret", "credential", "env", "sourcePath", "provider", "apiKey", "url", "hostname", "port", "path", "socket", "command", "endpoint", "image"} {
		if _, ok := raw[forbidden]; ok {
			t.Errorf("unsafe readiness gate policy metadata field %q should not be serialized", forbidden)
		}
	}

	metadata := original.EventMetadata()
	for _, key := range []string{"policyField", "decision", "outcome", "reason", "policyMode", "code", "counts"} {
		if _, ok := metadata[key]; !ok {
			t.Errorf("missing readiness gate policy event metadata key %q", key)
		}
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

	for _, key := range []string{"message", "summary", "metadata", "networkPolicyDecisionLogs"} {
		if _, ok := raw[key]; ok {
			t.Errorf("unexpected optional event field %q in %s", key, string(data))
		}
	}
}
