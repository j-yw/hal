package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/skills"
	"github.com/jywlabs/hal/internal/status"
	"github.com/jywlabs/hal/internal/template"
)

func setupHealthyContinueRepo(t *testing.T, dir string) string {
	t.Helper()
	t.Setenv("HOME", dir)
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	os.WriteFile(filepath.Join(halDir, template.ConfigFile), []byte("engine: pi\n"), 0644)
	os.WriteFile(filepath.Join(halDir, template.PromptFile), []byte("# Agent\n"), 0644)
	os.WriteFile(filepath.Join(halDir, template.ProgressFile), []byte("## Patterns\n"), 0644)

	skillsDir := filepath.Join(halDir, "skills")
	for _, name := range skills.ManagedSkillNames {
		os.MkdirAll(filepath.Join(skillsDir, name), 0755)
		os.WriteFile(filepath.Join(skillsDir, name, "SKILL.md"), []byte("# "+name), 0644)
	}
	commandsDir := filepath.Join(halDir, template.CommandsDir)
	os.MkdirAll(commandsDir, 0755)
	for _, name := range skills.CommandNames {
		os.WriteFile(filepath.Join(commandsDir, name+".md"), []byte("# "+name), 0644)
	}

	return halDir
}

func TestRunContinueFn_HealthyRepo(t *testing.T) {
	dir := t.TempDir()
	setupHealthyContinueRepo(t, dir)

	var buf bytes.Buffer
	if err := runContinueFn(dir, false, &buf); err != nil {
		t.Fatalf("runContinueFn() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Next:") {
		t.Fatalf("healthy output should contain 'Next:'\n%s", output)
	}
	if strings.Contains(output, "Fix:") {
		t.Fatalf("healthy output should not contain 'Fix:'\n%s", output)
	}
}

func TestRunContinueFn_AutoActiveOutputUsesSinglePipelineWording(t *testing.T) {
	dir := t.TempDir()
	halDir := setupHealthyContinueRepo(t, dir)
	os.WriteFile(filepath.Join(halDir, template.AutoStateFile), []byte(`{"step":"loop","branchName":"hal/auto-work"}`), 0644)

	var buf bytes.Buffer
	if err := runContinueFn(dir, false, &buf); err != nil {
		t.Fatalf("runContinueFn() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "State:") {
		t.Fatalf("output should contain state label\n%s", output)
	}
	if strings.Contains(output, "Workflow:") {
		t.Fatalf("output should not include legacy workflow label\n%s", output)
	}
	if !strings.Contains(output, "Step:     run") {
		t.Fatalf("output should show normalized auto step\n%s", output)
	}
	if !strings.Contains(output, "hal auto --resume") {
		t.Fatalf("output should recommend auto resume\n%s", output)
	}
	if strings.Contains(strings.ToLower(output), "compound") {
		t.Fatalf("output should not use legacy compound wording\n%s", output)
	}
}

func TestRunContinueFn_JSONAutoInactiveUsesSinglePipelineNextAction(t *testing.T) {
	dir := t.TempDir()
	halDir := setupHealthyContinueRepo(t, dir)
	os.WriteFile(filepath.Join(halDir, template.AutoStateFile), []byte(`{"step":"done"}`), 0644)

	var buf bytes.Buffer
	if err := runContinueFn(dir, true, &buf); err != nil {
		t.Fatalf("runContinueFn() error = %v", err)
	}

	var result ContinueResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON unmarshal error: %v\noutput: %s", err, buf.String())
	}

	if result.Status.State != status.StateAutoInactive {
		t.Fatalf("status.state = %q, want %q", result.Status.State, status.StateAutoInactive)
	}
	if result.Status.NextAction.ID != status.ActionRunAuto {
		t.Fatalf("status.nextAction.id = %q, want %q", result.Status.NextAction.ID, status.ActionRunAuto)
	}
	if result.NextCommand != "hal auto" {
		t.Fatalf("nextCommand = %q, want %q", result.NextCommand, "hal auto")
	}
	if !strings.Contains(result.NextDescription, "auto pipeline") {
		t.Fatalf("nextDescription should mention auto pipeline: %q", result.NextDescription)
	}
	if strings.Contains(strings.ToLower(result.NextDescription), "compound") {
		t.Fatalf("nextDescription should not mention legacy compound wording: %q", result.NextDescription)
	}
}

func TestRunContinueFn_UnhealthyRepo(t *testing.T) {
	dir := t.TempDir()
	// No .hal dir — doctor will fail

	var buf bytes.Buffer
	if err := runContinueFn(dir, false, &buf); err != nil {
		t.Fatalf("runContinueFn() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Fix:") {
		t.Fatalf("unhealthy output should contain 'Fix:'\n%s", output)
	}
	if !strings.Contains(output, "hal init") {
		t.Fatalf("unhealthy output should recommend 'hal init'\n%s", output)
	}
}

func TestRunContinueFn_JSONOutput(t *testing.T) {
	dir := t.TempDir()

	var buf bytes.Buffer
	if err := runContinueFn(dir, true, &buf); err != nil {
		t.Fatalf("runContinueFn() error = %v", err)
	}

	var result ContinueResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON unmarshal error: %v\noutput: %s", err, buf.String())
	}

	if result.ContractVersion != 1 {
		t.Fatalf("contractVersion = %d, want 1", result.ContractVersion)
	}
	if result.NextCommand == "" {
		t.Fatal("nextCommand should not be empty")
	}
	if result.Summary == "" {
		t.Fatal("summary should not be empty")
	}
}

func TestContinueCmdHelp(t *testing.T) {
	cmd := continueCmd

	if cmd.Use != "continue" {
		t.Fatalf("Use = %q, want %q", cmd.Use, "continue")
	}
	if cmd.Short == "" {
		t.Fatal("Short is empty")
	}
	if !strings.Contains(cmd.Example, "hal continue") {
		t.Fatalf("Example missing 'hal continue': %s", cmd.Example)
	}
}

func TestRunContinueFn_ReviewLoopComplete(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	halDir := filepath.Join(dir, template.HalDir)
	reportsDir := filepath.Join(halDir, "reports")
	os.MkdirAll(reportsDir, 0755)
	os.WriteFile(filepath.Join(halDir, template.ConfigFile), []byte("engine: pi\n"), 0644)
	os.WriteFile(filepath.Join(halDir, template.PromptFile), []byte("# Agent\n"), 0644)
	os.WriteFile(filepath.Join(halDir, template.ProgressFile), []byte("## P\n"), 0644)
	// Install skills and commands
	for _, name := range skills.ManagedSkillNames {
		os.MkdirAll(filepath.Join(halDir, "skills", name), 0755)
		os.WriteFile(filepath.Join(halDir, "skills", name, "SKILL.md"), []byte("# "+name), 0644)
	}
	commandsDir := filepath.Join(halDir, template.CommandsDir)
	os.MkdirAll(commandsDir, 0755)
	for _, name := range skills.CommandNames {
		os.WriteFile(filepath.Join(commandsDir, name+".md"), []byte("# "+name), 0644)
	}
	// Create review-loop report but no PRD
	os.WriteFile(filepath.Join(reportsDir, "review-loop-20260318-120000.json"), []byte(`{}`), 0644)

	var buf bytes.Buffer
	if err := runContinueFn(dir, true, &buf); err != nil {
		t.Fatalf("runContinueFn() error = %v", err)
	}

	var result ContinueResult
	json.Unmarshal(buf.Bytes(), &result)

	if result.Status.WorkflowTrack != "review_loop" {
		t.Fatalf("workflowTrack = %q, want review_loop", result.Status.WorkflowTrack)
	}
}

func TestRunContinueFn_JSONContainsBothStatusAndDoctor(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	var buf bytes.Buffer
	if err := runContinueFn(dir, true, &buf); err != nil {
		t.Fatalf("runContinueFn() error = %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	// Status should have its own contractVersion
	statusObj, ok := raw["status"].(map[string]interface{})
	if !ok {
		t.Fatal("status field should be an object")
	}
	if _, ok := statusObj["contractVersion"].(float64); !ok {
		t.Fatal("status.contractVersion should be a number")
	}
	if _, ok := statusObj["workflowTrack"].(string); !ok {
		t.Fatal("status.workflowTrack should be a string")
	}

	// Doctor should have its own contractVersion
	doctorObj, ok := raw["doctor"].(map[string]interface{})
	if !ok {
		t.Fatal("doctor field should be an object")
	}
	if _, ok := doctorObj["contractVersion"].(float64); !ok {
		t.Fatal("doctor.contractVersion should be a number")
	}
	if _, ok := doctorObj["overallStatus"].(string); !ok {
		t.Fatal("doctor.overallStatus should be a string")
	}
}

func TestRunContinueFn_ReadyField(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(string)
		wantReady bool
	}{
		{
			name: "no_hal_dir",
			setup: func(dir string) {
				// nothing
			},
			wantReady: false,
		},
		{
			name: "healthy_repo",
			setup: func(dir string) {
				halDir := filepath.Join(dir, template.HalDir)
				os.MkdirAll(filepath.Join(dir, ".git"), 0755)
				os.MkdirAll(halDir, 0755)
				os.WriteFile(filepath.Join(halDir, template.ConfigFile), []byte("engine: pi\n"), 0644)
				os.WriteFile(filepath.Join(halDir, template.PromptFile), []byte("# A\n"), 0644)
				os.WriteFile(filepath.Join(halDir, template.ProgressFile), []byte("## P\n"), 0644)
				for _, name := range skills.ManagedSkillNames {
					os.MkdirAll(filepath.Join(halDir, "skills", name), 0755)
					os.WriteFile(filepath.Join(halDir, "skills", name, "SKILL.md"), []byte("# "+name), 0644)
				}
				commandsDir := filepath.Join(halDir, template.CommandsDir)
				os.MkdirAll(commandsDir, 0755)
				for _, name := range skills.CommandNames {
					os.WriteFile(filepath.Join(commandsDir, name+".md"), []byte("# "+name), 0644)
				}
			},
			wantReady: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("HOME", dir)
			tt.setup(dir)

			var buf bytes.Buffer
			if err := runContinueFn(dir, true, &buf); err != nil {
				t.Fatalf("runContinueFn() error = %v", err)
			}

			var result ContinueResult
			json.Unmarshal(buf.Bytes(), &result)

			if result.Ready != tt.wantReady {
				t.Fatalf("ready = %v, want %v", result.Ready, tt.wantReady)
			}
		})
	}
}

func TestRunContinueFn_NoRedundantThen(t *testing.T) {
	// When doctor fix == workflow next, don't show "Then:"
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	// No .hal/ — fix is hal init, next is also hal init

	var buf bytes.Buffer
	if err := runContinueFn(dir, false, &buf); err != nil {
		t.Fatalf("runContinueFn() error = %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "Then:") {
		t.Fatalf("should not show 'Then:' when fix == next action\n%s", output)
	}
	if !strings.Contains(output, "Fix:") {
		t.Fatalf("should show 'Fix:'\n%s", output)
	}
}
