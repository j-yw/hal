package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
)

// TestCloudWorkflowOutputConformance_JSON_Detach runs all three workflow kinds
// (run, auto, review) against deterministic mocked backend responses and asserts
// that JSON output is parseable with the required contract fields: runId,
// workflowKind, and status.
func TestCloudWorkflowOutputConformance_JSON_Detach(t *testing.T) {
	tests := []struct {
		name         string
		workflowKind string
		runFn        func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error
	}{
		{
			name:         "run",
			workflowKind: "run",
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalRunCloud(flags, halDir, baseDir, sf, cf, out)
			},
		},
		{
			name:         "auto",
			workflowKind: "auto",
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalAutoCloud(flags, halDir, baseDir, sf, cf, out)
			},
		},
		{
			name:         "review",
			workflowKind: "review",
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalReviewCloud(flags, halDir, baseDir, sf, cf, out)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			setupHalDir(t, dir, map[string]string{
				"prd.json":     `{"project":"test"}`,
				"progress.txt": "## progress",
			})

			store := newCloudMockStore()
			store.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")

			runID := "conform-" + tt.name + "-001"

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
			err := tt.runFn(
				flags, dir+"/.hal", dir,
				func() (cloud.Store, error) { return store, nil },
				func() cloud.SubmitConfig {
					return cloud.SubmitConfig{IDFunc: func() string { return runID }}
				},
				&out,
			)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Parse as generic JSON map to assert contract fields.
			raw := strings.TrimSpace(out.String())
			var resp map[string]interface{}
			if err := json.Unmarshal([]byte(raw), &resp); err != nil {
				t.Fatalf("JSON output is not parseable: %v\nraw: %s", err, raw)
			}

			// Required fields: runId, workflowKind, status.
			for _, field := range []string{"runId", "workflowKind", "status"} {
				val, ok := resp[field]
				if !ok {
					t.Errorf("missing required JSON field %q", field)
					continue
				}
				s, ok := val.(string)
				if !ok || s == "" {
					t.Errorf("JSON field %q must be a non-empty string, got %v", field, val)
				}
			}

			// Assert correct workflowKind value.
			if got := resp["workflowKind"]; got != tt.workflowKind {
				t.Errorf("workflowKind = %q, want %q", got, tt.workflowKind)
			}

			// Assert run ID is deterministic.
			if got := resp["runId"]; got != runID {
				t.Errorf("runId = %q, want %q", got, runID)
			}

			// Status should be "queued" after submit.
			if got := resp["status"]; got != "queued" {
				t.Errorf("status = %q, want %q", got, "queued")
			}

			// Verify no mixed plain-text lines in JSON output.
			lines := strings.Split(raw, "\n")
			for i, line := range lines {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" {
					continue
				}
				// JSON lines start with {, }, or " (for indented fields).
				first := trimmed[0]
				if first != '{' && first != '}' && first != '"' {
					t.Errorf("line %d appears to be non-JSON: %q", i+1, line)
				}
			}
		})
	}
}

// TestCloudWorkflowOutputConformance_JSON_Wait runs all three workflow kinds in
// wait mode and asserts JSON output contains required fields after terminal status.
func TestCloudWorkflowOutputConformance_JSON_Wait(t *testing.T) {
	// Override poll intervals for fast tests.
	origRunPoll := runCloudPollInterval
	origAutoPoll := autoCloudPollInterval
	origReviewPoll := reviewCloudPollInterval
	runCloudPollInterval = 10 * time.Millisecond
	autoCloudPollInterval = 10 * time.Millisecond
	reviewCloudPollInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		runCloudPollInterval = origRunPoll
		autoCloudPollInterval = origAutoPoll
		reviewCloudPollInterval = origReviewPoll
	})

	tests := []struct {
		name         string
		workflowKind cloud.WorkflowKind
		runFn        func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error
	}{
		{
			name:         "run",
			workflowKind: cloud.WorkflowKindRun,
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalRunCloud(flags, halDir, baseDir, sf, cf, out)
			},
		},
		{
			name:         "auto",
			workflowKind: cloud.WorkflowKindAuto,
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalAutoCloud(flags, halDir, baseDir, sf, cf, out)
			},
		},
		{
			name:         "review",
			workflowKind: cloud.WorkflowKindReview,
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalReviewCloud(flags, halDir, baseDir, sf, cf, out)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			setupHalDir(t, dir, map[string]string{
				"prd.json":     `{"project":"test"}`,
				"progress.txt": "## progress",
			})

			store := newCloudMockStore()
			store.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")

			runID := "conform-wait-" + tt.name

			// Pre-populate terminal run for GetRun polling.
			store.runsByID[runID] = &cloud.Run{
				ID:           runID,
				WorkflowKind: tt.workflowKind,
				Status:       cloud.RunStatusSucceeded,
				Repo:         "org/repo",
				BaseBranch:   "main",
				CreatedAt:    time.Now().UTC(),
				UpdatedAt:    time.Now().UTC(),
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

			var out bytes.Buffer
			err := tt.runFn(
				flags, dir+"/.hal", dir,
				func() (cloud.Store, error) { return store, nil },
				func() cloud.SubmitConfig {
					return cloud.SubmitConfig{IDFunc: func() string { return runID }}
				},
				&out,
			)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			raw := strings.TrimSpace(out.String())
			var resp map[string]interface{}
			if err := json.Unmarshal([]byte(raw), &resp); err != nil {
				t.Fatalf("JSON output is not parseable: %v\nraw: %s", err, raw)
			}

			// Required fields: runId, workflowKind, status.
			for _, field := range []string{"runId", "workflowKind", "status"} {
				val, ok := resp[field]
				if !ok {
					t.Errorf("missing required JSON field %q", field)
					continue
				}
				s, ok := val.(string)
				if !ok || s == "" {
					t.Errorf("JSON field %q must be a non-empty string, got %v", field, val)
				}
			}

			if got := resp["workflowKind"]; got != tt.name {
				t.Errorf("workflowKind = %q, want %q", got, tt.name)
			}
			if got := resp["status"]; got != "succeeded" {
				t.Errorf("status = %q, want %q", got, "succeeded")
			}
		})
	}
}

// TestCloudWorkflowOutputConformance_Human_Detach runs all three workflow kinds
// in human mode and asserts summaries include run ID, status, and next-step hint.
func TestCloudWorkflowOutputConformance_Human_Detach(t *testing.T) {
	tests := []struct {
		name         string
		workflowKind string
		runFn        func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error
	}{
		{
			name:         "run",
			workflowKind: "run",
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalRunCloud(flags, halDir, baseDir, sf, cf, out)
			},
		},
		{
			name:         "auto",
			workflowKind: "auto",
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalAutoCloud(flags, halDir, baseDir, sf, cf, out)
			},
		},
		{
			name:         "review",
			workflowKind: "review",
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalReviewCloud(flags, halDir, baseDir, sf, cf, out)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			setupHalDir(t, dir, map[string]string{
				"prd.json":     `{"project":"test"}`,
				"progress.txt": "## progress",
			})

			store := newCloudMockStore()
			store.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")

			runID := "conform-human-" + tt.name

			flags := &CloudFlags{
				Cloud:            true,
				Detach:           true,
				CloudRepo:        "org/repo",
				CloudBase:        "main",
				CloudAuthProfile: "profile-1",
				CloudAuthScope:   "prd-123",
			}

			var out bytes.Buffer
			err := tt.runFn(
				flags, dir+"/.hal", dir,
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

			// AC3: Human-mode summaries include run ID.
			if !strings.Contains(output, runID) {
				t.Errorf("human output does not contain run ID %q\noutput: %s", runID, output)
			}

			// AC3: Human-mode summaries include status.
			if !strings.Contains(output, "queued") {
				t.Errorf("human output does not contain status 'queued'\noutput: %s", output)
			}

			// AC3: Human-mode summaries include next-step hint command.
			if !strings.Contains(output, "hal cloud status") {
				t.Errorf("human output does not contain next-step hint 'hal cloud status'\noutput: %s", output)
			}
		})
	}
}

// TestCloudWorkflowOutputConformance_Human_WaitTerminal runs all three workflow
// kinds in wait mode (human) and asserts terminal status and next-step hints.
func TestCloudWorkflowOutputConformance_Human_WaitTerminal(t *testing.T) {
	origRunPoll := runCloudPollInterval
	origAutoPoll := autoCloudPollInterval
	origReviewPoll := reviewCloudPollInterval
	runCloudPollInterval = 10 * time.Millisecond
	autoCloudPollInterval = 10 * time.Millisecond
	reviewCloudPollInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		runCloudPollInterval = origRunPoll
		autoCloudPollInterval = origAutoPoll
		reviewCloudPollInterval = origReviewPoll
	})

	tests := []struct {
		name         string
		workflowKind cloud.WorkflowKind
		runFn        func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error
		wantHints    []string // expected next-step hint substrings
	}{
		{
			name:         "run",
			workflowKind: cloud.WorkflowKindRun,
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalRunCloud(flags, halDir, baseDir, sf, cf, out)
			},
			wantHints: []string{"hal cloud logs"},
		},
		{
			name:         "auto",
			workflowKind: cloud.WorkflowKindAuto,
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalAutoCloud(flags, halDir, baseDir, sf, cf, out)
			},
			wantHints: []string{"hal cloud pull", "hal cloud logs"},
		},
		{
			name:         "review",
			workflowKind: cloud.WorkflowKindReview,
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalReviewCloud(flags, halDir, baseDir, sf, cf, out)
			},
			wantHints: []string{"hal cloud pull", "hal cloud logs"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			setupHalDir(t, dir, map[string]string{
				"prd.json":     `{"project":"test"}`,
				"progress.txt": "## progress",
			})

			store := newCloudMockStore()
			store.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")

			runID := "conform-terminal-" + tt.name

			// Pre-populate terminal run.
			store.runsByID[runID] = &cloud.Run{
				ID:           runID,
				WorkflowKind: tt.workflowKind,
				Status:       cloud.RunStatusSucceeded,
				Repo:         "org/repo",
				BaseBranch:   "main",
				CreatedAt:    time.Now().UTC(),
				UpdatedAt:    time.Now().UTC(),
			}

			flags := &CloudFlags{
				Cloud:            true,
				Wait:             true,
				CloudRepo:        "org/repo",
				CloudBase:        "main",
				CloudAuthProfile: "profile-1",
				CloudAuthScope:   "prd-123",
			}

			var out bytes.Buffer
			err := tt.runFn(
				flags, dir+"/.hal", dir,
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

			// AC3: Human-mode summaries include run ID.
			if !strings.Contains(output, runID) {
				t.Errorf("human output does not contain run ID %q\noutput: %s", runID, output)
			}

			// AC3: Human-mode summaries include terminal status.
			if !strings.Contains(output, "succeeded") {
				t.Errorf("human output does not contain terminal status 'succeeded'\noutput: %s", output)
			}

			// AC3: Human-mode summaries include next-step hint command.
			for _, hint := range tt.wantHints {
				if !strings.Contains(output, hint) {
					t.Errorf("human output does not contain next-step hint %q\noutput: %s", hint, output)
				}
			}
		})
	}
}

// TestCloudWorkflowOutputConformance_PrerequisiteFailure_JSON verifies that all
// three workflows return deterministic error fields in JSON mode for prerequisite
// failures (missing .hal directory).
func TestCloudWorkflowOutputConformance_PrerequisiteFailure_JSON(t *testing.T) {
	tests := []struct {
		name  string
		runFn func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error
	}{
		{
			name: "run",
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalRunCloud(flags, halDir, baseDir, sf, cf, out)
			},
		},
		{
			name: "auto",
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalAutoCloud(flags, halDir, baseDir, sf, cf, out)
			},
		},
		{
			name: "review",
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalReviewCloud(flags, halDir, baseDir, sf, cf, out)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			// Do NOT create .hal dir — this is the prerequisite failure.

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
			_ = tt.runFn(
				flags, dir+"/.hal", dir,
				func() (cloud.Store, error) { return store, nil },
				func() cloud.SubmitConfig {
					return cloud.SubmitConfig{IDFunc: func() string { return "unused" }}
				},
				&out,
			)

			raw := strings.TrimSpace(out.String())
			var resp map[string]interface{}
			if err := json.Unmarshal([]byte(raw), &resp); err != nil {
				t.Fatalf("JSON error output is not parseable: %v\nraw: %s", err, raw)
			}

			// Required error fields: error, error_code.
			for _, field := range []string{"error", "error_code"} {
				val, ok := resp[field]
				if !ok {
					t.Errorf("missing required JSON error field %q", field)
					continue
				}
				s, ok := val.(string)
				if !ok || s == "" {
					t.Errorf("JSON error field %q must be a non-empty string, got %v", field, val)
				}
			}

			// Assert deterministic error code.
			if got := resp["error_code"]; got != "prerequisite_error" {
				t.Errorf("error_code = %q, want %q", got, "prerequisite_error")
			}
		})
	}
}

// TestCloudWorkflowOutputConformance_PrerequisiteFailure_Human verifies that
// prerequisite failures in human mode include structured error fields for all
// three workflows.
func TestCloudWorkflowOutputConformance_PrerequisiteFailure_Human(t *testing.T) {
	tests := []struct {
		name  string
		runFn func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error
	}{
		{
			name: "run",
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalRunCloud(flags, halDir, baseDir, sf, cf, out)
			},
		},
		{
			name: "auto",
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalAutoCloud(flags, halDir, baseDir, sf, cf, out)
			},
		},
		{
			name: "review",
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalReviewCloud(flags, halDir, baseDir, sf, cf, out)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			// Do NOT create .hal dir — this is the prerequisite failure.

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
			err := tt.runFn(
				flags, dir+"/.hal", dir,
				func() (cloud.Store, error) { return store, nil },
				func() cloud.SubmitConfig {
					return cloud.SubmitConfig{IDFunc: func() string { return "unused" }}
				},
				&out,
			)

			// Human mode returns a Go error for non-zero exit.
			if err == nil {
				// auto and review writeAutoCloudError/writeReviewCloudError return
				// fmt.Errorf in human mode; run uses writeRunCloudError which also
				// returns an error. All should be non-nil for prerequisite failures.
				t.Fatalf("expected non-nil error for prerequisite failure")
			}

			// For hal run --cloud, human output includes structured error fields.
			// For hal auto/review --cloud, the error is returned directly.
			// Verify the error message references .hal or init.
			errMsg := err.Error()
			if !strings.Contains(errMsg, ".hal") && !strings.Contains(errMsg, "init") {
				t.Errorf("error message does not reference prerequisite: %q", errMsg)
			}
		})
	}
}

// TestCloudWorkflowOutputConformance_ConfigError_JSON verifies that
// configuration errors (nil store factory) produce deterministic JSON error
// fields across all three workflows.
func TestCloudWorkflowOutputConformance_ConfigError_JSON(t *testing.T) {
	tests := []struct {
		name  string
		runFn func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error
	}{
		{
			name: "run",
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalRunCloud(flags, halDir, baseDir, sf, cf, out)
			},
		},
		{
			name: "auto",
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalAutoCloud(flags, halDir, baseDir, sf, cf, out)
			},
		},
		{
			name: "review",
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalReviewCloud(flags, halDir, baseDir, sf, cf, out)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			setupHalDir(t, dir, map[string]string{
				"prd.json":     `{"project":"test"}`,
				"progress.txt": "## progress",
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
			// Pass nil store factory to trigger configuration error.
			_ = tt.runFn(
				flags, dir+"/.hal", dir,
				nil,
				func() cloud.SubmitConfig {
					return cloud.SubmitConfig{IDFunc: func() string { return "unused" }}
				},
				&out,
			)

			raw := strings.TrimSpace(out.String())
			var resp map[string]interface{}
			if err := json.Unmarshal([]byte(raw), &resp); err != nil {
				t.Fatalf("JSON error output is not parseable: %v\nraw: %s", err, raw)
			}

			for _, field := range []string{"error", "error_code"} {
				val, ok := resp[field]
				if !ok {
					t.Errorf("missing required JSON error field %q", field)
					continue
				}
				s, ok := val.(string)
				if !ok || s == "" {
					t.Errorf("JSON error field %q must be a non-empty string, got %v", field, val)
				}
			}

			if got := resp["error_code"]; got != "configuration_error" {
				t.Errorf("error_code = %q, want %q", got, "configuration_error")
			}
		})
	}
}

// TestCloudWorkflowOutputConformance_FlagConflict_JSON verifies that the
// --detach/--wait flag conflict produces a deterministic error across all
// three workflows with the same error code.
func TestCloudWorkflowOutputConformance_FlagConflict_JSON(t *testing.T) {
	tests := []struct {
		name  string
		runFn func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error
	}{
		{
			name: "run",
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalRunCloud(flags, halDir, baseDir, sf, cf, out)
			},
		},
		{
			name: "auto",
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalAutoCloud(flags, halDir, baseDir, sf, cf, out)
			},
		},
		{
			name: "review",
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalReviewCloud(flags, halDir, baseDir, sf, cf, out)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			setupHalDir(t, dir, map[string]string{
				"prd.json": `{"project":"test"}`,
			})

			store := newCloudMockStore()
			store.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")

			flags := &CloudFlags{
				Cloud:            true,
				Detach:           true,
				Wait:             true, // conflict with Detach
				JSON:             true,
				CloudRepo:        "org/repo",
				CloudBase:        "main",
				CloudAuthProfile: "profile-1",
				CloudAuthScope:   "prd-123",
			}

			var out bytes.Buffer
			_ = tt.runFn(
				flags, dir+"/.hal", dir,
				func() (cloud.Store, error) { return store, nil },
				func() cloud.SubmitConfig {
					return cloud.SubmitConfig{IDFunc: func() string { return "unused" }}
				},
				&out,
			)

			raw := strings.TrimSpace(out.String())
			var resp map[string]interface{}
			if err := json.Unmarshal([]byte(raw), &resp); err != nil {
				t.Fatalf("JSON error output is not parseable: %v\nraw: %s", err, raw)
			}

			if got := resp["error_code"]; got != "invalid_flag_combination" {
				t.Errorf("error_code = %q, want %q", got, "invalid_flag_combination")
			}
		})
	}
}

// TestCloudWorkflowOutputConformance_WorkflowKindConsistency verifies that each
// workflow kind is correctly reflected in the JSON response across detach and
// wait modes, locking the contract against regressions.
func TestCloudWorkflowOutputConformance_WorkflowKindConsistency(t *testing.T) {
	origRunPoll := runCloudPollInterval
	origAutoPoll := autoCloudPollInterval
	origReviewPoll := reviewCloudPollInterval
	runCloudPollInterval = 10 * time.Millisecond
	autoCloudPollInterval = 10 * time.Millisecond
	reviewCloudPollInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		runCloudPollInterval = origRunPoll
		autoCloudPollInterval = origAutoPoll
		reviewCloudPollInterval = origReviewPoll
	})

	tests := []struct {
		name         string
		workflowKind cloud.WorkflowKind
		runFn        func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error
	}{
		{
			name:         "run",
			workflowKind: cloud.WorkflowKindRun,
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalRunCloud(flags, halDir, baseDir, sf, cf, out)
			},
		},
		{
			name:         "auto",
			workflowKind: cloud.WorkflowKindAuto,
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalAutoCloud(flags, halDir, baseDir, sf, cf, out)
			},
		},
		{
			name:         "review",
			workflowKind: cloud.WorkflowKindReview,
			runFn: func(flags *CloudFlags, halDir, baseDir string, sf func() (cloud.Store, error), cf func() cloud.SubmitConfig, out *bytes.Buffer) error {
				return runHalReviewCloud(flags, halDir, baseDir, sf, cf, out)
			},
		},
	}

	for _, tt := range tests {
		// Test both detach and wait produce consistent workflowKind.
		for _, mode := range []string{"detach", "wait"} {
			t.Run(tt.name+"/"+mode, func(t *testing.T) {
				dir := t.TempDir()
				setupHalDir(t, dir, map[string]string{
					"prd.json":     `{"project":"test"}`,
					"progress.txt": "## progress",
				})

				store := newCloudMockStore()
				store.profiles["profile-1"] = linkedCloudProfile("profile-1", "anthropic")

				runID := "conform-kind-" + tt.name + "-" + mode
				store.runsByID[runID] = &cloud.Run{
					ID:           runID,
					WorkflowKind: tt.workflowKind,
					Status:       cloud.RunStatusSucceeded,
					Repo:         "org/repo",
					BaseBranch:   "main",
					CreatedAt:    time.Now().UTC(),
					UpdatedAt:    time.Now().UTC(),
				}

				flags := &CloudFlags{
					Cloud:            true,
					Detach:           mode == "detach",
					Wait:             mode == "wait",
					JSON:             true,
					CloudRepo:        "org/repo",
					CloudBase:        "main",
					CloudAuthProfile: "profile-1",
					CloudAuthScope:   "prd-123",
				}

				var out bytes.Buffer
				err := tt.runFn(
					flags, dir+"/.hal", dir,
					func() (cloud.Store, error) { return store, nil },
					func() cloud.SubmitConfig {
						return cloud.SubmitConfig{IDFunc: func() string { return runID }}
					},
					&out,
				)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				raw := strings.TrimSpace(out.String())
				var resp map[string]interface{}
				if err := json.Unmarshal([]byte(raw), &resp); err != nil {
					t.Fatalf("JSON not parseable: %v\nraw: %s", err, raw)
				}

				if got := resp["workflowKind"]; got != string(tt.workflowKind) {
					t.Errorf("workflowKind = %q, want %q", got, tt.workflowKind)
				}
			})
		}
	}
}
