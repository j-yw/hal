package factory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadHandoffSummaryFailedLocalRun(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 9, 0, 0, 0, time.UTC)
	record := RunRecord{
		RunID:        "run-local",
		Status:       RunStatusFailed,
		ExecutorMode: ExecutorModeLocal,
		RepoPath:     "/workspace/hal",
		BranchName:   "hal/factory-handoff",
		CurrentStep:  "ci",
		CreatedAt:    createdAt,
		UpdatedAt:    createdAt.Add(time.Minute),
		Failure: &FailureSummary{
			Step:        "ci",
			Category:    FailureCategoryCI,
			Message:     "ci gate blocked",
			Recoverable: true,
		},
	}
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error = %v", err)
	}

	saveHandoffArtifact(t, store, record.RunID, ArtifactReference{
		ID:   "auto-state",
		Name: "auto-state",
		Type: "json",
		Path: ".hal/auto-state.json",
	}, `{"step":"ci"}`)
	saveHandoffArtifact(t, store, record.RunID, ArtifactReference{
		ID:   "pr-outcome",
		Name: "pr-outcome",
		Type: "json",
		Path: "factory/pr-outcome.json",
	}, `{"pullRequestUrl":"https://github.com/jywlabs/hal/pull/42"}`)
	saveHandoffArtifact(t, store, record.RunID, ArtifactReference{
		ID:   "ci-log",
		Name: "ci-log",
		Type: "text",
		Path: ".hal/reports/ci-output.log",
	}, "ci failed")

	summary, err := LoadHandoffSummary(store, record.RunID)
	if err != nil {
		t.Fatalf("LoadHandoffSummary() error = %v", err)
	}

	if !summary.HandoffRequired {
		t.Fatal("HandoffRequired = false, want true")
	}
	if summary.RepoPath != record.RepoPath {
		t.Fatalf("RepoPath = %q, want %q", summary.RepoPath, record.RepoPath)
	}
	if summary.BranchName != record.BranchName {
		t.Fatalf("BranchName = %q, want %q", summary.BranchName, record.BranchName)
	}
	if summary.CurrentStep != "ci" {
		t.Fatalf("CurrentStep = %q, want ci", summary.CurrentStep)
	}
	if summary.FailureReason != "ci gate blocked" {
		t.Fatalf("FailureReason = %q", summary.FailureReason)
	}
	if summary.ResumeCommand != "hal auto --resume" {
		t.Fatalf("ResumeCommand = %q, want hal auto --resume", summary.ResumeCommand)
	}
	if summary.PullRequestURL != "https://github.com/jywlabs/hal/pull/42" {
		t.Fatalf("PullRequestURL = %q", summary.PullRequestURL)
	}
	if summary.NextAction == nil {
		t.Fatal("NextAction = nil, want resume action")
	}
	if summary.NextAction.ID != "resume_auto" || summary.NextAction.Type != NextActionTypeContinue || summary.NextAction.Command != "hal auto --resume" {
		t.Fatalf("NextAction = %#v, want resume_auto continue action", summary.NextAction)
	}
	if len(summary.ArtifactLocations) != 2 {
		t.Fatalf("ArtifactLocations len = %d, want 2: %#v", len(summary.ArtifactLocations), summary.ArtifactLocations)
	}
	if len(summary.LogLocations) != 1 {
		t.Fatalf("LogLocations len = %d, want 1: %#v", len(summary.LogLocations), summary.LogLocations)
	}
	if summary.LogLocations[0].StoredPath == "" {
		t.Fatalf("log location should include stored path: %#v", summary.LogLocations[0])
	}
}

func TestLoadHandoffSummaryFailedSandboxRun(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 10, 0, 0, 0, time.UTC)
	record := RunRecord{
		RunID:        "run-sandbox",
		Status:       RunStatusFailed,
		ExecutorMode: ExecutorModeSandbox,
		BranchName:   "hal/factory-handoff",
		SandboxName:  "fallback-sandbox",
		Sandbox: &SandboxMetadata{
			Name:       "factory-remote",
			SSHCommand: "ssh root@203.0.113.10",
			Connection: &SandboxConnectionMetadata{
				Address:           "203.0.113.10",
				PublicIP:          "203.0.113.10",
				TailscaleIP:       "100.64.0.10",
				TailscaleHostname: "factory.tailnet.ts.net",
			},
		},
		CurrentStep: "run",
		CreatedAt:   createdAt,
		UpdatedAt:   createdAt.Add(time.Minute),
		Failure: &FailureSummary{
			Step:        "run",
			Category:    FailureCategoryPipeline,
			Message:     "remote execution failed",
			Recoverable: true,
		},
		Artifacts: []ArtifactReference{
			{
				ID:      "sandbox-reports",
				Name:    "sandbox-reports",
				Type:    "directory",
				Path:    ".hal/reports",
				Partial: true,
			},
			{
				ID:         "sandbox-stdout",
				Name:       "sandbox-stdout",
				Type:       "text",
				Path:       ".hal/reports/stdout.txt",
				StoredPath: "artifacts/run-sandbox/sandbox-stdout.txt",
			},
			{
				ID:   "pr-outcome",
				Name: "pr-outcome",
				Type: "json",
				Path: "factory/pr-outcome.json",
				Summary: map[string]any{
					"pullRequestUrl": "https://github.com/jywlabs/hal/pull/77",
				},
			},
		},
	}
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error = %v", err)
	}

	summary, err := LoadHandoffSummary(store, record.RunID)
	if err != nil {
		t.Fatalf("LoadHandoffSummary() error = %v", err)
	}

	if !summary.HandoffRequired {
		t.Fatal("HandoffRequired = false, want true")
	}
	if summary.SandboxName != "factory-remote" {
		t.Fatalf("SandboxName = %q, want factory-remote", summary.SandboxName)
	}
	if summary.SSHCommand != "hal sandbox ssh factory-remote" {
		t.Fatalf("SSHCommand = %q", summary.SSHCommand)
	}
	if summary.ResumeCommand != "" {
		t.Fatalf("ResumeCommand = %q, want empty", summary.ResumeCommand)
	}
	if summary.PullRequestURL != "https://github.com/jywlabs/hal/pull/77" {
		t.Fatalf("PullRequestURL = %q", summary.PullRequestURL)
	}
	if summary.NextAction == nil {
		t.Fatal("NextAction = nil, want sandbox takeover action")
	}
	if summary.NextAction.Type != NextActionTypeTakeover || summary.NextAction.Command != "hal sandbox ssh factory-remote" {
		t.Fatalf("NextAction = %#v, want sandbox takeover", summary.NextAction)
	}
	if len(summary.ArtifactLocations) != 2 {
		t.Fatalf("ArtifactLocations len = %d, want 2: %#v", len(summary.ArtifactLocations), summary.ArtifactLocations)
	}
	if len(summary.LogLocations) != 1 {
		t.Fatalf("LogLocations len = %d, want 1: %#v", len(summary.LogLocations), summary.LogLocations)
	}

	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	for _, forbidden := range []string{"203.0.113.10", "100.64.0.10", "tailnet.ts.net", "root@"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("handoff summary should not expose %q: %s", forbidden, string(data))
		}
	}
}

func TestLoadHandoffSummaryUnsafeSandboxNameFallsBackToInspect(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 10, 30, 0, 0, time.UTC)
	record := RunRecord{
		RunID:        "run-unsafe-sandbox",
		Status:       RunStatusFailed,
		ExecutorMode: ExecutorModeSandbox,
		SandboxName:  "fallback;rm",
		Sandbox: &SandboxMetadata{
			Name: "factory-remote;rm",
		},
		CreatedAt: createdAt,
		UpdatedAt: createdAt.Add(time.Minute),
		Failure: &FailureSummary{
			Step:        "run",
			Category:    FailureCategoryPipeline,
			Message:     "remote execution failed",
			Recoverable: true,
		},
	}
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error = %v", err)
	}

	summary, err := LoadHandoffSummary(store, record.RunID)
	if err != nil {
		t.Fatalf("LoadHandoffSummary() error = %v", err)
	}

	if summary.SandboxName != "" {
		t.Fatalf("SandboxName = %q, want empty invalid name", summary.SandboxName)
	}
	if summary.SSHCommand != "" {
		t.Fatalf("SSHCommand = %q, want empty", summary.SSHCommand)
	}
	if summary.NextAction == nil {
		t.Fatal("NextAction = nil, want inspect action")
	}
	if summary.NextAction.ID != handoffInspectActionID || summary.NextAction.Type != NextActionTypeInspect {
		t.Fatalf("NextAction = %#v, want inspect action", summary.NextAction)
	}
	if summary.NextAction.Command != "hal factory status run-unsafe-sandbox --json" {
		t.Fatalf("NextAction.Command = %q", summary.NextAction.Command)
	}
}

func TestLoadHandoffSummaryCompletedRunHasNoTakeoverGuidance(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 11, 0, 0, 0, time.UTC)
	finishedAt := createdAt.Add(5 * time.Minute)
	record := RunRecord{
		RunID:        "run-complete",
		Status:       RunStatusSucceeded,
		ExecutorMode: ExecutorModeLocal,
		RepoPath:     "/workspace/hal",
		BranchName:   "hal/factory-handoff",
		CurrentStep:  "done",
		CreatedAt:    createdAt,
		UpdatedAt:    finishedAt,
		FinishedAt:   &finishedAt,
		Artifacts: []ArtifactReference{
			{Name: "report", Type: "markdown", Path: ".hal/reports/review.md"},
		},
	}
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error = %v", err)
	}

	summary, err := LoadHandoffSummary(store, record.RunID)
	if err != nil {
		t.Fatalf("LoadHandoffSummary() error = %v", err)
	}

	if summary.HandoffRequired {
		t.Fatal("HandoffRequired = true, want false")
	}
	if summary.NextAction != nil {
		t.Fatalf("NextAction = %#v, want nil", summary.NextAction)
	}
	if summary.ResumeCommand != "" {
		t.Fatalf("ResumeCommand = %q, want empty", summary.ResumeCommand)
	}
	if summary.SSHCommand != "" {
		t.Fatalf("SSHCommand = %q, want empty", summary.SSHCommand)
	}
	if summary.FailureReason != "" {
		t.Fatalf("FailureReason = %q, want empty", summary.FailureReason)
	}
	if summary.InspectCommand != "hal factory status run-complete --json" {
		t.Fatalf("InspectCommand = %q", summary.InspectCommand)
	}
}

func TestHandoffInspectCommandRejectsUnsafeRunIDs(t *testing.T) {
	tests := []struct {
		runID string
		want  string
	}{
		{runID: "run-safe_001.2", want: "hal factory status run-safe_001.2 --json"},
		{runID: "run unsafe", want: ""},
		{runID: "run;rm", want: ""},
		{runID: "run$(rm)", want: ""},
		{runID: "../run", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.runID, func(t *testing.T) {
			if got := HandoffInspectCommand(tt.runID); got != tt.want {
				t.Fatalf("HandoffInspectCommand(%q) = %q, want %q", tt.runID, got, tt.want)
			}
		})
	}
}

func TestHandoffSafeURLRejectsSecretQueryKeys(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "safe pr url",
			raw:  "https://github.com/jywlabs/hal/pull/42",
			want: "https://github.com/jywlabs/hal/pull/42",
		},
		{
			name: "token query",
			raw:  "https://github.com/jywlabs/hal/pull/42?token=secret",
			want: "",
		},
		{
			name: "access key query",
			raw:  "https://github.com/jywlabs/hal/pull/42?access_key=secret",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := handoffSafeURL(tt.raw); got != tt.want {
				t.Fatalf("handoffSafeURL(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestHandoffArtifactLocationsSanitizeUnsafeDisplayPaths(t *testing.T) {
	rawPath := filepath.Join(t.TempDir(), "external", "secret.md")
	locations := handoffArtifactLocations([]ArtifactReference{
		{
			Name:       "absolute",
			Type:       "markdown",
			Path:       rawPath,
			StoredPath: "artifacts/run-handoff/secret.md",
		},
		{
			Name:       "url",
			Type:       "json",
			Path:       "https://example.com/artifact.json?token=secret",
			StoredPath: "artifacts/run-handoff/artifact.json",
		},
		{
			Name: "parent",
			Type: "markdown",
			Path: "../private.md",
		},
	}, false)

	if len(locations) != 3 {
		t.Fatalf("locations len = %d, want 3: %#v", len(locations), locations)
	}
	if locations[0].Path != "secret.md" {
		t.Fatalf("absolute path = %q, want basename", locations[0].Path)
	}
	if locations[1].Path != "" || locations[1].StoredPath != "artifacts/run-handoff/artifact.json" {
		t.Fatalf("url location = %#v, want stored path fallback", locations[1])
	}
	if locations[2].Path != "[redacted]" {
		t.Fatalf("parent path = %q, want [redacted]", locations[2].Path)
	}

	data, err := json.Marshal(locations)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	for _, forbidden := range []string{rawPath, filepath.Dir(rawPath), "token=secret", "../private.md"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("locations should not expose %q: %s", forbidden, string(data))
		}
	}
}

func saveHandoffArtifact(t *testing.T, store Store, runID string, artifact ArtifactReference, content string) ArtifactReference {
	t.Helper()
	sourcePath := filepath.Join(t.TempDir(), strings.Trim(strings.ReplaceAll(artifact.Path, "/", "-"), "-"))
	if sourcePath == filepath.Dir(sourcePath) {
		sourcePath = filepath.Join(t.TempDir(), "artifact")
	}
	if err := os.WriteFile(sourcePath, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", sourcePath, err)
	}
	stored, err := store.SaveArtifactFile(runID, artifact, sourcePath)
	if err != nil {
		t.Fatalf("SaveArtifactFile(%s) error = %v", artifact.Name, err)
	}
	return stored
}
