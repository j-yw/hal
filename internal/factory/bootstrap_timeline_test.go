package factory

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBootstrapTimelineEventFromStepRecordsSuccessfulCommand(t *testing.T) {
	secret := "ghp_timeline_success_secret_value"
	request := BootstrapRequest{
		RequiredEnvKeys: []string{"GITHUB_TOKEN"},
		Env: map[string]string{
			"GITHUB_TOKEN": secret,
		},
	}
	startedAt := time.Date(2026, 6, 21, 8, 30, 0, 0, time.UTC)
	finishedAt := startedAt.Add(2 * time.Second)

	event := BootstrapTimelineEventFromStep(request, BootstrapStepResult{
		Name:           BootstrapStepCloneRepository,
		Status:         RunStatusSucceeded,
		CommandSummary: "git clone https://" + secret + "@github.com/jywlabs/hal.git /workspace/hal",
		StartedAt:      startedAt,
		FinishedAt:     &finishedAt,
	}, BootstrapCommandResult{
		OutputSummary: "repository cloned with " + secret,
		Metadata: map[string]string{
			"GITHUB_TOKEN": secret,
			"remote":       "origin",
		},
	}, nil)

	if !event.Timestamp.Equal(finishedAt) {
		t.Fatalf("event timestamp = %s, want %s", event.Timestamp, finishedAt)
	}
	if event.Step != BootstrapStepCloneRepository {
		t.Fatalf("event step = %q, want %q", event.Step, BootstrapStepCloneRepository)
	}
	if event.Status != RunStatusSucceeded {
		t.Fatalf("event status = %q, want %q", event.Status, RunStatusSucceeded)
	}
	if event.Message != "bootstrap step succeeded" {
		t.Fatalf("event message = %q", event.Message)
	}
	if !strings.Contains(event.CommandSummary, bootstrapRedactedValue) {
		t.Fatalf("command summary was not redacted: %q", event.CommandSummary)
	}
	if event.OutputSummary != "repository cloned with "+bootstrapRedactedValue {
		t.Fatalf("output summary = %q", event.OutputSummary)
	}
	if event.Metadata["remote"] != "origin" {
		t.Fatalf("metadata remote = %q, want origin", event.Metadata["remote"])
	}
	if event.Metadata["exitCode"] != "0" {
		t.Fatalf("metadata exitCode = %q, want 0", event.Metadata["exitCode"])
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal(event) error = %v", err)
	}
	assertDoesNotContainSensitiveFixture(t, data, secret)
}

func TestBootstrapTimelineEventFromStepRecordsFailedCommandClassification(t *testing.T) {
	secret := "github_pat_timeline_failure_secret_value"
	request := BootstrapRequest{
		RequiredEnvKeys: []string{"GITHUB_TOKEN"},
		Env: map[string]string{
			"GITHUB_TOKEN": secret,
		},
	}
	startedAt := time.Date(2026, 6, 21, 8, 45, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	failure := &BootstrapFailure{
		Step:     BootstrapStepCloneRepository,
		Category: BootstrapFailureCategoryAuth,
		Message:  "authentication failed for GITHUB_TOKEN=" + secret,
	}

	event := BootstrapTimelineEventFromStep(request, BootstrapStepResult{
		Name:           BootstrapStepCloneRepository,
		Status:         RunStatusFailed,
		CommandSummary: "git clone https://" + secret + "@github.com/jywlabs/hal.git /workspace/hal",
		StartedAt:      startedAt,
		FinishedAt:     &finishedAt,
		ExitCode:       128,
	}, BootstrapCommandResult{
		StderrSummary: "remote rejected " + secret,
		Metadata: map[string]string{
			"remote": "origin",
		},
	}, failure)

	if event.Message != "authentication failed for "+bootstrapRedactedEnvKey+"="+bootstrapRedactedValue {
		t.Fatalf("event message = %q", event.Message)
	}
	if event.Metadata[bootstrapTimelineFailureCategoryKey] != BootstrapFailureCategoryAuth {
		t.Fatalf("failure category metadata = %q, want %q", event.Metadata[bootstrapTimelineFailureCategoryKey], BootstrapFailureCategoryAuth)
	}
	if event.Metadata["exitCode"] != "128" {
		t.Fatalf("metadata exitCode = %q, want 128", event.Metadata["exitCode"])
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal(event) error = %v", err)
	}
	assertDoesNotContainSensitiveFixture(t, data, secret)
}

func TestBootstrapRefreshHalRecordsTimelineForEachStep(t *testing.T) {
	executor := &fakeBootstrapExecutor{
		results: []BootstrapCommandResult{
			{
				ExitCode:      0,
				OutputSummary: "hal installed from checkout",
				Metadata: map[string]string{
					"command": "install",
				},
			},
			{
				ExitCode:      0,
				OutputSummary: "hal templates refreshed",
				Metadata: map[string]string{
					"command": "init",
				},
			},
			{
				ExitCode:      0,
				OutputSummary: "hal skill links refreshed",
				Metadata: map[string]string{
					"command": "links refresh",
				},
			},
		},
	}

	result, err := BootstrapRefreshHal(context.Background(), BootstrapRequest{WorkspaceDir: "/workspace/hal"}, BootstrapHalDeps{
		Executor: executor,
		Now:      incrementingClock(t, time.Date(2026, 6, 21, 9, 0, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatalf("BootstrapRefreshHal() error = %v", err)
	}
	if len(result.Timeline) != len(result.Steps) {
		t.Fatalf("timeline length = %d, steps length = %d", len(result.Timeline), len(result.Steps))
	}
	for i, step := range result.Steps {
		event := result.Timeline[i]
		if event.Step != step.Name {
			t.Fatalf("timeline[%d] step = %q, want %q", i, event.Step, step.Name)
		}
		if event.Status != step.Status {
			t.Fatalf("timeline[%d] status = %q, want %q", i, event.Status, step.Status)
		}
		if event.CommandSummary != step.CommandSummary {
			t.Fatalf("timeline[%d] command summary = %q, want %q", i, event.CommandSummary, step.CommandSummary)
		}
		if event.OutputSummary == "" {
			t.Fatalf("timeline[%d] missing output summary", i)
		}
		if event.Metadata["exitCode"] != "0" {
			t.Fatalf("timeline[%d] exit code metadata = %q, want 0", i, event.Metadata["exitCode"])
		}
	}
}
