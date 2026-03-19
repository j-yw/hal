package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

func newAutoTestCommand(t *testing.T) (*cobra.Command, *bytes.Buffer) {
	t.Helper()

	cmd := &cobra.Command{Use: "auto"}
	cmd.Flags().Bool("dry-run", false, "")
	cmd.Flags().Bool("resume", false, "")
	cmd.Flags().Bool("skip-pr", false, "")
	cmd.Flags().String("report", "", "")
	cmd.Flags().String("engine", "codex", "")
	cmd.Flags().String("base", "", "")
	cmd.Flags().Bool("json", false, "")

	var out bytes.Buffer
	cmd.SetOut(&out)

	return cmd, &out
}

func chdirTemp(t *testing.T) {
	t.Helper()

	tmpDir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(wd)
	})
}

func TestRunAuto_JSONNoReportsReturnsJSONOnly(t *testing.T) {
	chdirTemp(t)

	cmd, out := newAutoTestCommand(t)
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set json flag: %v", err)
	}

	if err := runAuto(cmd, nil); err != nil {
		t.Fatalf("runAuto returned error: %v", err)
	}

	if !json.Valid(out.Bytes()) {
		t.Fatalf("stdout is not valid JSON: %q", out.String())
	}

	var result AutoResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if result.OK {
		t.Fatalf("result.OK = true, want false")
	}
	if !strings.Contains(result.Error, "reports directory does not exist") {
		t.Fatalf("result.Error = %q, want reports directory guidance", result.Error)
	}
	if result.NextAction == nil {
		t.Fatal("result.NextAction should not be nil")
	}
	if result.NextAction.ID != "run_auto" {
		t.Fatalf("result.NextAction.ID = %q, want run_auto", result.NextAction.ID)
	}
	if strings.Contains(out.String(), "No reports found.") {
		t.Fatalf("stdout should not include text-mode message: %q", out.String())
	}
	if strings.Contains(out.String(), "compound pipeline") {
		t.Fatalf("stdout should not include command header: %q", out.String())
	}
}

func TestRunAuto_JSONResumeWithoutStateReturnsJSONOnly(t *testing.T) {
	chdirTemp(t)

	cmd, out := newAutoTestCommand(t)
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set json flag: %v", err)
	}
	if err := cmd.Flags().Set("resume", "true"); err != nil {
		t.Fatalf("set resume flag: %v", err)
	}

	if err := runAuto(cmd, nil); err != nil {
		t.Fatalf("runAuto returned error: %v", err)
	}

	if !json.Valid(out.Bytes()) {
		t.Fatalf("stdout is not valid JSON: %q", out.String())
	}

	var result AutoResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if result.OK {
		t.Fatalf("result.OK = true, want false")
	}
	if result.Error != "no saved state to resume from" {
		t.Fatalf("result.Error = %q, want no saved state to resume from", result.Error)
	}
	if result.NextAction == nil {
		t.Fatal("result.NextAction should not be nil")
	}
	if result.NextAction.ID != "run_auto" {
		t.Fatalf("result.NextAction.ID = %q, want run_auto", result.NextAction.ID)
	}
	if strings.Contains(out.String(), "Resuming pipeline") {
		t.Fatalf("stdout should not include text-mode resume output: %q", out.String())
	}
	if strings.Contains(out.String(), "compound pipeline") {
		t.Fatalf("stdout should not include command header: %q", out.String())
	}
}

func TestRunAuto_JSONResumeWithDoneStateReturnsJSONOnly(t *testing.T) {
	chdirTemp(t)

	halDir := template.HalDir
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	statePath := filepath.Join(halDir, template.AutoStateFile)
	if err := os.WriteFile(statePath, []byte(`{"step":"done"}`), 0644); err != nil {
		t.Fatalf("write auto-state.json: %v", err)
	}

	cmd, out := newAutoTestCommand(t)
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set json flag: %v", err)
	}
	if err := cmd.Flags().Set("resume", "true"); err != nil {
		t.Fatalf("set resume flag: %v", err)
	}

	if err := runAuto(cmd, nil); err != nil {
		t.Fatalf("runAuto returned error: %v", err)
	}

	if !json.Valid(out.Bytes()) {
		t.Fatalf("stdout is not valid JSON: %q", out.String())
	}

	var result AutoResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if !result.OK {
		t.Fatalf("result.OK = false, want true; output: %q", out.String())
	}
	if strings.Contains(out.String(), "Resuming from step") {
		t.Fatalf("stdout should not include pipeline resume output: %q", out.String())
	}
}

func TestOutputAutoJSON_FailureNextAction(t *testing.T) {
	tests := []struct {
		name        string
		failure     autoFailureKind
		resumable   bool
		wantID      string
		wantCommand string
	}{
		{
			name:        "config failure suggests init",
			failure:     autoFailureConfig,
			resumable:   false,
			wantID:      "run_init",
			wantCommand: "hal init",
		},
		{
			name:        "no reports suggests auto with report",
			failure:     autoFailureNoReports,
			resumable:   false,
			wantID:      "run_auto",
			wantCommand: "hal auto --report <path>",
		},
		{
			name:        "pipeline failure with resumable state suggests resume",
			failure:     autoFailurePipeline,
			resumable:   true,
			wantID:      "resume_auto",
			wantCommand: "hal auto --resume",
		},
		{
			name:        "pipeline failure without state suggests rerun",
			failure:     autoFailurePipeline,
			resumable:   false,
			wantID:      "run_auto",
			wantCommand: "hal auto",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			err := outputAutoJSON(&out, false, false, "failed", tt.failure, tt.resumable)
			if err != nil {
				t.Fatalf("outputAutoJSON returned error: %v", err)
			}

			if !json.Valid(out.Bytes()) {
				t.Fatalf("stdout is not valid JSON: %q", out.String())
			}

			var result AutoResult
			if err := json.Unmarshal(out.Bytes(), &result); err != nil {
				t.Fatalf("unmarshal output: %v", err)
			}

			if result.NextAction == nil {
				t.Fatal("result.NextAction should not be nil")
			}
			if result.NextAction.ID != tt.wantID {
				t.Fatalf("result.NextAction.ID = %q, want %q", result.NextAction.ID, tt.wantID)
			}
			if result.NextAction.Command != tt.wantCommand {
				t.Fatalf("result.NextAction.Command = %q, want %q", result.NextAction.Command, tt.wantCommand)
			}
		})
	}
}
