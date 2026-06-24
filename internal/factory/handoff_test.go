package factory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
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

func TestLoadHandoffSummaryRedactsSensitiveRepoPath(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	record := RunRecord{
		RunID:        "run-sensitive-repo-path",
		Status:       RunStatusFailed,
		ExecutorMode: ExecutorModeLocal,
		RepoPath:     "/workspace/token=secret-value/project",
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

	summary, err := LoadHandoffSummary(store, record.RunID)
	if err != nil {
		t.Fatalf("LoadHandoffSummary() error = %v", err)
	}
	if summary.RepoPath != "" {
		t.Fatalf("RepoPath = %q, want empty for sensitive path", summary.RepoPath)
	}
	if summary.ResumeCommand != "" {
		t.Fatalf("ResumeCommand = %q, want empty for sensitive repo path", summary.ResumeCommand)
	}
	if summary.NextAction == nil {
		t.Fatal("NextAction = nil, want inspect action")
	}
	if summary.NextAction.ID != "inspect_factory_run" || summary.NextAction.Type != NextActionTypeInspect {
		t.Fatalf("NextAction = %#v, want inspect action", summary.NextAction)
	}
	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if strings.Contains(string(data), "token=secret-value") || strings.Contains(string(data), record.RepoPath) {
		t.Fatalf("handoff summary should not expose sensitive repo path: %s", string(data))
	}
}

func TestLoadHandoffSummaryRedactsSensitiveBranchAndStep(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	record := RunRecord{
		RunID:        "run-sensitive-handoff-context",
		Status:       RunStatusFailed,
		ExecutorMode: ExecutorModeLocal,
		BranchName:   "hal/token=secret-value",
		CurrentStep:  "ci",
		Failure: &FailureSummary{
			Step:        "/workspace/token=secret-value/ci",
			Category:    FailureCategoryCI,
			Message:     "ci gate blocked",
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
	if summary.BranchName != "[redacted]" {
		t.Fatalf("BranchName = %q, want [redacted]", summary.BranchName)
	}
	if summary.CurrentStep != "[redacted]" {
		t.Fatalf("CurrentStep = %q, want [redacted]", summary.CurrentStep)
	}
	if summary.NextAction == nil {
		t.Fatal("NextAction = nil, want inspect action")
	}
	if summary.NextAction.BranchName != "[redacted]" {
		t.Fatalf("NextAction.BranchName = %q, want [redacted]", summary.NextAction.BranchName)
	}
	if summary.NextAction.CurrentStep != "[redacted]" {
		t.Fatalf("NextAction.CurrentStep = %q, want [redacted]", summary.NextAction.CurrentStep)
	}
}

func TestLoadHandoffSummaryDropsPullRequestURLWithSecretQueryValue(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	record := RunRecord{
		RunID:        "run-sensitive-pr",
		Status:       RunStatusFailed,
		ExecutorMode: ExecutorModeLocal,
	}
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error = %v", err)
	}

	saveHandoffArtifact(t, store, record.RunID, ArtifactReference{
		ID:   "pr-outcome",
		Name: "pr-outcome",
		Type: "json",
		Path: "factory/pr-outcome.json",
	}, `{"pullRequestUrl":"https://github.com/jywlabs/hal/pull/42?ref=ghp_secret"}`)

	summary, err := LoadHandoffSummary(store, record.RunID)
	if err != nil {
		t.Fatalf("LoadHandoffSummary() error = %v", err)
	}
	if summary.PullRequestURL != "" {
		t.Fatalf("PullRequestURL = %q, want empty", summary.PullRequestURL)
	}
}

func TestLoadHandoffSummaryRedactsSensitiveFailureReason(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	record := RunRecord{
		RunID:        "run-sensitive-failure",
		Status:       RunStatusFailed,
		ExecutorMode: ExecutorModeLocal,
		Failure: &FailureSummary{
			Step:        "ci",
			Category:    FailureCategoryCI,
			Message:     "ci failed against 203.0.113.10 with token=secret-value",
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

	if summary.FailureReason != "[redacted]" {
		t.Fatalf("FailureReason = %q, want [redacted]", summary.FailureReason)
	}
	if summary.NextAction == nil {
		t.Fatal("NextAction = nil, want inspect action")
	}
	if summary.NextAction.FailureReason != "[redacted]" {
		t.Fatalf("NextAction.FailureReason = %q, want [redacted]", summary.NextAction.FailureReason)
	}
}

func TestLoadHandoffSummaryRedactsSSHHostnameFailureReason(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	record := RunRecord{
		RunID:        "run-sensitive-ssh-host",
		Status:       RunStatusFailed,
		ExecutorMode: ExecutorModeLocal,
		Failure: &FailureSummary{
			Step:        "run",
			Category:    FailureCategoryPipeline,
			Message:     "remote command failed: ssh ubuntu@sandbox.example.com:22 failed",
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

	if summary.FailureReason != "[redacted]" {
		t.Fatalf("FailureReason = %q, want [redacted]", summary.FailureReason)
	}
	if summary.NextAction == nil {
		t.Fatal("NextAction = nil, want inspect action")
	}
	if summary.NextAction.FailureReason != "[redacted]" {
		t.Fatalf("NextAction.FailureReason = %q, want [redacted]", summary.NextAction.FailureReason)
	}
	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	for _, forbidden := range []string{"sandbox.example.com", "ubuntu@"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("handoff summary should not expose %q: %s", forbidden, string(data))
		}
	}
}

func TestSanitizeHandoffFailureReasonRedactsBareSecretValues(t *testing.T) {
	tests := []string{
		"authentication failed for token ghp_xxx",
		"authentication failed for token <ghp_xxx>",
		"authentication failed for --token ghp_xxx",
		"authentication failed for --api-key sk-secretvalue",
		"authentication failed for Authorization Bearer ghp_xxx",
		"provider returned ghp_xxx",
		"engine returned sk-secretvalue",
	}
	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			if got := SanitizeHandoffFailureReason(tt); got != "[redacted]" {
				t.Fatalf("SanitizeHandoffFailureReason() = %q, want [redacted]", got)
			}
		})
	}
}

func TestSanitizeHandoffFailureReasonRedactsMultilineMessages(t *testing.T) {
	tests := []string{
		"pipeline failed\nstderr line",
		"pipeline failed\rstderr line",
		"pipeline failed\r\nstderr line",
	}
	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			if got := SanitizeHandoffFailureReason(tt); got != "[redacted]" {
				t.Fatalf("SanitizeHandoffFailureReason() = %q, want [redacted]", got)
			}
		})
	}
}

func TestSanitizeHandoffFailureReasonRedactsFileURLPaths(t *testing.T) {
	tests := []string{
		"local log available at file:///Users/example/.hal/reports/failure.txt",
		"local log available at file://localhost/Users/example/.hal/reports/failure.txt",
	}
	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			if got := SanitizeHandoffFailureReason(tt); got != "[redacted]" {
				t.Fatalf("SanitizeHandoffFailureReason() = %q, want [redacted]", got)
			}
		})
	}
}

func TestSanitizeHandoffFailureReasonRedactsSecretURLQueryValues(t *testing.T) {
	reason := "ci failed: https://github.com/jywlabs/hal/pull/42?ref=ghp_secret"
	if got := SanitizeHandoffFailureReason(reason); got != "[redacted]" {
		t.Fatalf("SanitizeHandoffFailureReason() = %q, want [redacted]", got)
	}
}

func TestSanitizeHandoffFailureReasonRedactsURLHosts(t *testing.T) {
	reason := "failed fetching https://runner.internal:8443/logs"
	if got := SanitizeHandoffFailureReason(reason); got != "[redacted]" {
		t.Fatalf("SanitizeHandoffFailureReason() = %q, want [redacted]", got)
	}
}

func TestSanitizeHandoffFailureReasonRedactsBareDNSHostnames(t *testing.T) {
	tests := []string{
		"dial tcp db.internal.example.com:5432: connect: refused",
		"dial tcp runner.internal:8443: connect: refused",
		"lookup ci.internal.example.com: no such host",
		"failed to fetch runner.internal/logs",
	}
	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			if got := SanitizeHandoffFailureReason(tt); got != "[redacted]" {
				t.Fatalf("SanitizeHandoffFailureReason() = %q, want [redacted]", got)
			}
		})
	}
}

func TestSanitizeHandoffFailureReasonRedactsSecretURLFragmentValues(t *testing.T) {
	reason := "ci failed: https://example.com/callback#access_token=ghp_secret"
	if got := SanitizeHandoffFailureReason(reason); got != "[redacted]" {
		t.Fatalf("SanitizeHandoffFailureReason() = %q, want [redacted]", got)
	}
}

func TestSanitizeHandoffFailureReasonRedactsSSHHostnames(t *testing.T) {
	tests := []string{
		"remote command failed: ssh ubuntu@sandbox.example.com:22 failed",
		"remote command failed: ssh -o StrictHostKeyChecking=no ubuntu@sandbox.example.com failed",
		"remote command failed: ssh sandbox.example.com failed",
		"remote connection failed: ssh://sandbox.example.com",
		"provider returned ubuntu@sandbox.example.com:22",
		"provider returned deploy@prod",
		"provider returned git@runner.internal:org/repo.git",
		"remote command failed: ssh prod failed",
	}
	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			if got := SanitizeHandoffFailureReason(tt); got != "[redacted]" {
				t.Fatalf("SanitizeHandoffFailureReason() = %q, want [redacted]", got)
			}
		})
	}
}

func TestLoadHandoffSummaryRedactsFailureReasonAddressWithPort(t *testing.T) {
	tests := []struct {
		name    string
		message string
	}{
		{
			name:    "address with port",
			message: "connection failed to 203.0.113.10:22",
		},
		{
			name:    "go dial tcp address with trailing colon",
			message: "dial tcp 10.0.0.1:443: connect: refused",
		},
		{
			name:    "go dial tcp ipv6 address with trailing colon",
			message: "dial tcp [2001:db8::1]:443: connect: refused",
		},
		{
			name:    "go dial tcp dns hostname with trailing colon",
			message: "dial tcp db.internal.example.com:5432: connect: refused",
		},
		{
			name:    "bare dns hostname without port",
			message: "connection failed to runner.internal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewStore(filepath.Join(t.TempDir(), "factory"))
			record := RunRecord{
				RunID:        "run-sensitive-port",
				Status:       RunStatusFailed,
				ExecutorMode: ExecutorModeLocal,
				Failure: &FailureSummary{
					Step:        "run",
					Category:    FailureCategoryPipeline,
					Message:     tt.message,
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
			if summary.FailureReason != "[redacted]" {
				t.Fatalf("FailureReason = %q, want [redacted]", summary.FailureReason)
			}
			if summary.NextAction == nil {
				t.Fatal("NextAction = nil, want inspect action")
			}
			if summary.NextAction.FailureReason != "[redacted]" {
				t.Fatalf("NextAction.FailureReason = %q, want [redacted]", summary.NextAction.FailureReason)
			}
		})
	}
}

func TestLoadHandoffSummaryPreservesFailureReasonWithDocumentationPlaceholders(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	message := `step ci failed: failed to create PR: git remote "origin" is not configured; set origin to git@github.com:<owner>/<repo>.git or https://github.com/<owner>/<repo>.git`
	record := RunRecord{
		RunID:        "run-placeholder-failure",
		Status:       RunStatusFailed,
		ExecutorMode: ExecutorModeLocal,
		Failure: &FailureSummary{
			Step:        "ci",
			Category:    FailureCategoryCI,
			Message:     message,
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
	if summary.FailureReason != message {
		t.Fatalf("FailureReason = %q, want original actionable message", summary.FailureReason)
	}
}

func TestLoadHandoffSummaryIgnoresArchivedAutoStateArtifact(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 9, 10, 0, 0, time.UTC)
	record := RunRecord{
		RunID:        "run-archived-auto-state",
		Status:       RunStatusFailed,
		ExecutorMode: ExecutorModeLocal,
		RepoPath:     "/workspace/hal",
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
		ID:   "archived-auto-state",
		Name: "auto-state",
		Type: "json",
		Path: ".hal/archive/2026-06-21-factory/.hal/auto-state.json",
	}, `{"step":"ci"}`)

	summary, err := LoadHandoffSummary(store, record.RunID)
	if err != nil {
		t.Fatalf("LoadHandoffSummary() error = %v", err)
	}
	if summary.ResumeCommand != "" {
		t.Fatalf("ResumeCommand = %q, want empty for archived auto-state", summary.ResumeCommand)
	}
	if summary.NextAction == nil {
		t.Fatal("NextAction = nil, want inspect action")
	}
	if summary.NextAction.ID != handoffInspectActionID || summary.NextAction.Type != NextActionTypeInspect {
		t.Fatalf("NextAction = %#v, want inspect action", summary.NextAction)
	}
	if summary.NextAction.Command != "hal factory status run-archived-auto-state --json" {
		t.Fatalf("NextAction.Command = %q", summary.NextAction.Command)
	}
}

func TestLoadHandoffSummaryFailedLocalRunWithoutRepoPathFallsBackToInspect(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 9, 15, 0, 0, time.UTC)
	record := RunRecord{
		RunID:        "run-local-no-repo",
		Status:       RunStatusFailed,
		ExecutorMode: ExecutorModeLocal,
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

	summary, err := LoadHandoffSummary(store, record.RunID)
	if err != nil {
		t.Fatalf("LoadHandoffSummary() error = %v", err)
	}
	if summary.ResumeCommand != "" {
		t.Fatalf("ResumeCommand = %q, want empty without repo path", summary.ResumeCommand)
	}
	if summary.NextAction == nil {
		t.Fatal("NextAction = nil, want inspect action")
	}
	if summary.NextAction.ID != "inspect_factory_run" || summary.NextAction.Type != NextActionTypeInspect {
		t.Fatalf("NextAction = %#v, want inspect action", summary.NextAction)
	}
	if summary.NextAction.Command != "hal factory status run-local-no-repo --json" {
		t.Fatalf("NextAction.Command = %q", summary.NextAction.Command)
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
			Status:     sandbox.StatusRunning,
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

func TestLoadHandoffSummaryFailedSandboxRunNotRunningFallsBackToInspect(t *testing.T) {
	tests := []struct {
		name   string
		status string
	}{
		{name: "stopped", status: sandbox.StatusStopped},
		{name: "unknown", status: sandbox.StatusUnknown},
		{name: "empty", status: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewStore(filepath.Join(t.TempDir(), "factory"))
			createdAt := time.Date(2026, 6, 21, 10, 15, 0, 0, time.UTC)
			record := RunRecord{
				RunID:        "run-sandbox-" + tt.name,
				Status:       RunStatusFailed,
				ExecutorMode: ExecutorModeSandbox,
				SandboxName:  "factory-remote",
				Sandbox: &SandboxMetadata{
					Name:   "factory-remote",
					Status: tt.status,
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
			if summary.SSHCommand != "" {
				t.Fatalf("SSHCommand = %q, want empty for status %q", summary.SSHCommand, tt.status)
			}
			if summary.NextAction == nil {
				t.Fatal("NextAction = nil, want inspect action")
			}
			if summary.NextAction.ID != handoffInspectActionID || summary.NextAction.Type != NextActionTypeInspect {
				t.Fatalf("NextAction = %#v, want inspect action", summary.NextAction)
			}
			if summary.NextAction.Command != "hal factory status "+record.RunID+" --json" {
				t.Fatalf("NextAction.Command = %q", summary.NextAction.Command)
			}
		})
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

func TestHandoffSafeURLRejectsSecretQuerySecrets(t *testing.T) {
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
			name: "safe query value",
			raw:  "https://github.com/jywlabs/hal/pull/42?ref=ci-main",
			want: "https://github.com/jywlabs/hal/pull/42?ref=ci-main",
		},
		{
			name: "private dns host",
			raw:  "https://github.internal.corp/jywlabs/hal/pull/42",
			want: "",
		},
		{
			name: "host with port",
			raw:  "https://github.com:8443/jywlabs/hal/pull/42",
			want: "",
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
		{
			name: "secret query value",
			raw:  "https://github.com/jywlabs/hal/pull/42?ref=ghp_secret",
			want: "",
		},
		{
			name: "ip query value",
			raw:  "https://github.com/jywlabs/hal/pull/42?runner=203.0.113.10:22",
			want: "",
		},
		{
			name: "ssh query value",
			raw:  "https://github.com/jywlabs/hal/pull/42?target=git@runner.internal",
			want: "",
		},
		{
			name: "unparsable secret query",
			raw:  "https://github.com/jywlabs/hal/pull/42?access_token=ghp_secret;foo=bar",
			want: "",
		},
		{
			name: "token fragment",
			raw:  "https://github.com/jywlabs/hal/pull/42#token=secret",
			want: "",
		},
		{
			name: "secret fragment value",
			raw:  "https://github.com/jywlabs/hal/pull/42#ref=ghp_secret",
			want: "",
		},
		{
			name: "ip fragment value",
			raw:  "https://github.com/jywlabs/hal/pull/42#203.0.113.10",
			want: "",
		},
		{
			name: "ssh fragment value",
			raw:  "https://github.com/jywlabs/hal/pull/42#git@runner.internal",
			want: "",
		},
		{
			name: "secret path prefix",
			raw:  "https://github.com/jywlabs/hal/ghp_secretvalue123",
			want: "",
		},
		{
			name: "escaped secret path prefix",
			raw:  "https://github.com/jywlabs/hal/%67%68%70%5Fsecretvalue123",
			want: "",
		},
		{
			name: "secret path assignment",
			raw:  "https://github.com/jywlabs/hal/token=secret",
			want: "",
		},
		{
			name: "secret path segment value",
			raw:  "https://github.com/jywlabs/hal/token/secret-value",
			want: "",
		},
		{
			name: "ip path segment",
			raw:  "https://github.com/jywlabs/hal/203.0.113.10.log",
			want: "",
		},
		{
			name: "ssh path segment",
			raw:  "https://github.com/jywlabs/hal/git@runner.internal/repo",
			want: "",
		},
		{
			name: "safe fragment",
			raw:  "https://github.com/jywlabs/hal/pull/42#discussion_r123",
			want: "https://github.com/jywlabs/hal/pull/42#discussion_r123",
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
	secretBasePath := filepath.Join(t.TempDir(), "external", "api_key=sk-secret.json")
	locations := handoffArtifactLocations("run-handoff", []ArtifactReference{
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
		{
			Name: "relative-secret",
			Type: "json",
			Path: ".hal/reports/token=ghp_secret.json",
		},
		{
			Name: "absolute-secret-base",
			Type: "json",
			Path: secretBasePath,
		},
		{
			Name: "ip-segment",
			Type: "json",
			Path: "reports/10.0.0.1/output.json",
		},
		{
			Name: "ssh-host-segment",
			Type: "json",
			Path: "reports/user@example-1.com:22/output.json",
		},
	}, false)

	if len(locations) != 7 {
		t.Fatalf("locations len = %d, want 7: %#v", len(locations), locations)
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
	for i := 3; i < len(locations); i++ {
		if locations[i].Path != "[redacted]" {
			t.Fatalf("locations[%d].Path = %q, want [redacted]", i, locations[i].Path)
		}
	}

	data, err := json.Marshal(locations)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	for _, forbidden := range []string{rawPath, filepath.Dir(rawPath), "token=secret", "../private.md", "ghp_secret", "sk-secret", "10.0.0.1", "example-1.com"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("locations should not expose %q: %s", forbidden, string(data))
		}
	}
}

func TestHandoffArtifactLocationsSanitizeUnsafeStoredPaths(t *testing.T) {
	locations := handoffArtifactLocations("run-handoff", []ArtifactReference{
		{
			Name:       "url",
			Type:       "json",
			Path:       "https://example.com/artifact.json?token=secret",
			StoredPath: "https://example.com/artifact.json?token=secret",
		},
		{
			Name:       "wrong-run",
			Type:       "json",
			Path:       "safe.json",
			StoredPath: "artifacts/other-run/artifact.json",
		},
		{
			Name:       "parent",
			Type:       "json",
			Path:       "parent.json",
			StoredPath: "artifacts/run-handoff/../private.json",
		},
		{
			Name:       "token",
			Type:       "json",
			Path:       "token.json",
			StoredPath: "artifacts/run-handoff/token=ghp_secret.json",
		},
		{
			Name:       "ip-stored-path",
			Type:       "json",
			Path:       "ip-stored-path.json",
			StoredPath: "artifacts/run-handoff/203.0.113.10.json",
		},
		{
			Name:       "ssh-stored-path",
			Type:       "json",
			Path:       "ssh-stored-path.json",
			StoredPath: "artifacts/run-handoff/git@runner.internal:org-repo.json",
		},
	}, false)

	if len(locations) != 6 {
		t.Fatalf("locations len = %d, want 6: %#v", len(locations), locations)
	}
	if locations[0].Path != "[redacted]" || locations[0].StoredPath != "" {
		t.Fatalf("url location = %#v, want redacted display without stored path", locations[0])
	}
	for i := 1; i < len(locations); i++ {
		if locations[i].StoredPath != "" {
			t.Fatalf("locations[%d].StoredPath = %q, want empty", i, locations[i].StoredPath)
		}
	}

	data, err := json.Marshal(locations)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	for _, forbidden := range []string{"https://example.com", "other-run", "../private", "ghp_secret", "203.0.113.10", "runner.internal"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("locations should not expose %q: %s", forbidden, string(data))
		}
	}
}

func TestHandoffArtifactLocationsSanitizeUnsafeNames(t *testing.T) {
	rawPath := filepath.Join(t.TempDir(), "external", "secret.json")
	artifacts := []ArtifactReference{
		{
			Name:       "https://10.0.0.1/artifact.json?token=secret",
			Type:       "json",
			Path:       "artifact.json",
			StoredPath: "artifacts/run-handoff/artifact.json",
		},
		{
			Name: "token ghp_secret",
			Type: "json",
			Path: "secret.json",
		},
		{
			Name:       "stderr\n" + rawPath,
			Type:       "log",
			Path:       "stderr.log",
			StoredPath: "artifacts/run-handoff/stderr.log",
		},
	}

	artifactLocations := handoffArtifactLocations("run-handoff", artifacts, false)
	if len(artifactLocations) != 2 {
		t.Fatalf("artifact locations len = %d, want 2: %#v", len(artifactLocations), artifactLocations)
	}
	for i, location := range artifactLocations {
		if location.Name != "artifact" {
			t.Fatalf("artifactLocations[%d].Name = %q, want artifact", i, location.Name)
		}
	}

	logLocations := handoffArtifactLocations("run-handoff", artifacts, true)
	if len(logLocations) != 1 {
		t.Fatalf("log locations len = %d, want 1: %#v", len(logLocations), logLocations)
	}
	if logLocations[0].Name != "log" {
		t.Fatalf("log location name = %q, want log", logLocations[0].Name)
	}

	data, err := json.Marshal(struct {
		Artifacts []NextActionLocation `json:"artifacts"`
		Logs      []NextActionLocation `json:"logs"`
	}{
		Artifacts: artifactLocations,
		Logs:      logLocations,
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	for _, forbidden := range []string{"10.0.0.1", "token=secret", "ghp_secret", rawPath, "\n"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("locations should not expose %q: %s", forbidden, string(data))
		}
	}
}

func TestHandoffArtifactLooksLikeLogRequiresToken(t *testing.T) {
	tests := []struct {
		name     string
		artifact ArtifactReference
		want     bool
	}{
		{
			name: "log name token",
			artifact: ArtifactReference{
				Name: "ci-log",
				Type: "text",
				Path: ".hal/reports/ci-output.txt",
			},
			want: true,
		},
		{
			name: "stdout path token",
			artifact: ArtifactReference{
				Name: "verification-output",
				Type: "text",
				Path: ".hal/reports/verify/test-stdout.txt",
			},
			want: true,
		},
		{
			name: "log extension",
			artifact: ArtifactReference{
				Name: "ci-output",
				Type: "text",
				Path: ".hal/reports/ci-output.log",
			},
			want: true,
		},
		{
			name: "catalog artifact",
			artifact: ArtifactReference{
				Name:       "catalog",
				Type:       "json",
				Path:       "factory/catalog.json",
				StoredPath: "artifacts/run-catalog/catalog.json",
			},
			want: false,
		},
		{
			name: "changelog artifact",
			artifact: ArtifactReference{
				Name:       "changelog",
				Type:       "markdown",
				Path:       "docs/changelog.md",
				StoredPath: "artifacts/run-changelog/changelog.md",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := handoffArtifactLooksLikeLog(tt.artifact); got != tt.want {
				t.Fatalf("handoffArtifactLooksLikeLog() = %v, want %v", got, tt.want)
			}
		})
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
