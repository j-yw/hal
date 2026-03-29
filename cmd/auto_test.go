package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

func newAutoTestCommand(t *testing.T) (*cobra.Command, *bytes.Buffer) {
	t.Helper()

	cmd := &cobra.Command{Use: "auto"}
	cmd.Flags().Bool("dry-run", false, "")
	cmd.Flags().Bool("resume", false, "")
	cmd.Flags().Bool("skip-ci", false, "")
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

func assertAutoJSONContractV2(t *testing.T, data []byte) {
	t.Helper()

	if !json.Valid(data) {
		t.Fatalf("stdout is not valid JSON: %q", string(data))
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw output: %v", err)
	}

	requiredTopLevelFields := []string{"contractVersion", "ok", "entryMode", "resumed", "steps", "summary"}
	for _, field := range requiredTopLevelFields {
		if _, ok := raw[field]; !ok {
			t.Fatalf("auto JSON missing required top-level field %q", field)
		}
	}

	if version, ok := raw["contractVersion"].(float64); !ok || int(version) != 2 {
		t.Fatalf("contractVersion = %v, want 2", raw["contractVersion"])
	}

	steps, ok := raw["steps"].(map[string]interface{})
	if !ok {
		t.Fatalf("steps should be an object, got %T", raw["steps"])
	}

	requiredStepKeys := []string{"analyze", "spec", "branch", "convert", "validate", "run", "review", "report", "ci", "archive"}
	validStatuses := map[string]bool{"completed": true, "skipped": true, "failed": true, "pending": true}
	for _, stepKey := range requiredStepKeys {
		stepRaw, ok := steps[stepKey]
		if !ok {
			t.Fatalf("steps missing required key %q", stepKey)
		}
		stepObj, ok := stepRaw.(map[string]interface{})
		if !ok {
			t.Fatalf("steps.%s should be an object, got %T", stepKey, stepRaw)
		}
		status, ok := stepObj["status"].(string)
		if !ok {
			t.Fatalf("steps.%s.status should be a string", stepKey)
		}
		if !validStatuses[status] {
			t.Fatalf("steps.%s.status = %q, want one of completed/skipped/failed/pending", stepKey, status)
		}
	}
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

	assertAutoJSONContractV2(t, out.Bytes())

	var result AutoResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if result.OK {
		t.Fatalf("result.OK = true, want false")
	}
	if result.EntryMode != string(autoEntryModeReportDiscovery) {
		t.Fatalf("result.EntryMode = %q, want %q", result.EntryMode, autoEntryModeReportDiscovery)
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

	assertAutoJSONContractV2(t, out.Bytes())

	var result AutoResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if result.OK {
		t.Fatalf("result.OK = true, want false")
	}
	if result.Resumed != true {
		t.Fatalf("result.Resumed = false, want true")
	}
	if result.EntryMode != string(autoEntryModeReportDiscovery) {
		t.Fatalf("result.EntryMode = %q, want %q", result.EntryMode, autoEntryModeReportDiscovery)
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

	assertAutoJSONContractV2(t, out.Bytes())

	var result AutoResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if !result.OK {
		t.Fatalf("result.OK = false, want true; output: %q", out.String())
	}
	if result.ContractVersion != 2 {
		t.Fatalf("result.ContractVersion = %d, want 2", result.ContractVersion)
	}
	if strings.Contains(out.String(), "Resuming from step") {
		t.Fatalf("stdout should not include pipeline resume output: %q", out.String())
	}
}

func TestRunAuto_ResumeIgnoresPositionalAndReportInputs(t *testing.T) {
	chdirTemp(t)

	halDir := template.HalDir
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	statePath := filepath.Join(halDir, template.AutoStateFile)
	if err := os.WriteFile(statePath, []byte(`{"step":"done"}`), 0644); err != nil {
		t.Fatalf("write auto-state.json: %v", err)
	}

	reportPath := filepath.Join(".", "report.md")
	if err := os.WriteFile(reportPath, []byte("# Report\n"), 0644); err != nil {
		t.Fatalf("write report: %v", err)
	}
	mdPath := filepath.Join(".", "feature.md")
	if err := os.WriteFile(mdPath, []byte("# PRD: Resume Ignore Inputs\n"), 0644); err != nil {
		t.Fatalf("write markdown: %v", err)
	}

	cmd, out := newAutoTestCommand(t)
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set json flag: %v", err)
	}
	if err := cmd.Flags().Set("resume", "true"); err != nil {
		t.Fatalf("set resume flag: %v", err)
	}
	if err := cmd.Flags().Set("report", reportPath); err != nil {
		t.Fatalf("set report flag: %v", err)
	}
	var errOut bytes.Buffer
	cmd.SetErr(&errOut)

	if err := runAuto(cmd, []string{mdPath}); err != nil {
		t.Fatalf("runAuto returned error: %v", err)
	}

	assertAutoJSONContractV2(t, out.Bytes())

	var result AutoResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if result.EntryMode != string(autoEntryModeReportDiscovery) {
		t.Fatalf("result.EntryMode = %q, want %q", result.EntryMode, autoEntryModeReportDiscovery)
	}

	warnings := errOut.String()
	if !strings.Contains(warnings, "warning: --resume ignores positional prd-path; using saved state") {
		t.Fatalf("expected positional-path ignore warning, got %q", warnings)
	}
	if !strings.Contains(warnings, "warning: --resume ignores --report; using saved state") {
		t.Fatalf("expected --report ignore warning, got %q", warnings)
	}
}

func TestRunAuto_MigratesLegacyAutoPRDAtStartup(t *testing.T) {
	chdirTemp(t)

	halDir := template.HalDir
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}

	prdPath := filepath.Join(halDir, template.PRDFile)
	if err := os.WriteFile(prdPath, []byte(`{"project":"new","branchName":"hal/new","userStories":[]}`), 0644); err != nil {
		t.Fatalf("write prd.json: %v", err)
	}

	autoPath := filepath.Join(halDir, template.AutoPRDFile)
	if err := os.WriteFile(autoPath, []byte(`{"project":"old","branchName":"hal/old","userStories":[]}`), 0644); err != nil {
		t.Fatalf("write auto-prd.json: %v", err)
	}

	cmd, out := newAutoTestCommand(t)
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set json flag: %v", err)
	}
	var errOut bytes.Buffer
	cmd.SetErr(&errOut)

	if err := runAuto(cmd, nil); err != nil {
		t.Fatalf("runAuto returned error: %v", err)
	}

	assertAutoJSONContractV2(t, out.Bytes())

	if _, err := os.Stat(autoPath); !os.IsNotExist(err) {
		t.Fatalf("auto-prd.json should be migrated away, stat err=%v", err)
	}

	legacyMatches, err := filepath.Glob(filepath.Join(halDir, "auto-prd.legacy-*.json"))
	if err != nil {
		t.Fatalf("glob legacy auto-prd files: %v", err)
	}
	if len(legacyMatches) != 1 {
		t.Fatalf("legacy backup count = %d, want 1", len(legacyMatches))
	}

	warn := errOut.String()
	if !strings.Contains(warn, "warning: auto-prd.json differs from prd.json; preserved legacy file at .hal/auto-prd.legacy-") {
		t.Fatalf("expected migration warning on stderr, got %q", warn)
	}
}

func TestRunAuto_DryRunWithPositionalMarkdownStartsFromBranch(t *testing.T) {
	chdirTemp(t)

	mdPath := filepath.Join(".", "feature-prd.md")
	if err := os.WriteFile(mdPath, []byte("# PRD: Positional Entry\n\n## Scope\n- test\n"), 0644); err != nil {
		t.Fatalf("write markdown: %v", err)
	}

	cmd, out := newAutoTestCommand(t)
	if err := cmd.Flags().Set("dry-run", "true"); err != nil {
		t.Fatalf("set dry-run flag: %v", err)
	}

	if err := runAuto(cmd, []string{mdPath}); err != nil {
		t.Fatalf("runAuto returned error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Step: branch") {
		t.Fatalf("expected branch step in output, got %q", output)
	}
	if !strings.Contains(output, "Step: convert") {
		t.Fatalf("expected convert step in output, got %q", output)
	}
	if strings.Contains(output, "Step: analyze") {
		t.Fatalf("positional markdown should skip analyze, output=%q", output)
	}
	if strings.Contains(output, "Step: spec") {
		t.Fatalf("positional markdown should skip spec, output=%q", output)
	}
}

func TestRunAuto_DryRunWithoutPositionalMarkdownRunsAnalyzeSpecBranchBeforeConvert(t *testing.T) {
	chdirTemp(t)

	reportPath := filepath.Join(".", "report.md")
	if err := os.WriteFile(reportPath, []byte("# Report\n"), 0644); err != nil {
		t.Fatalf("write report: %v", err)
	}

	cmd, out := newAutoTestCommand(t)
	if err := cmd.Flags().Set("dry-run", "true"); err != nil {
		t.Fatalf("set dry-run flag: %v", err)
	}
	if err := cmd.Flags().Set("report", reportPath); err != nil {
		t.Fatalf("set report flag: %v", err)
	}

	if err := runAuto(cmd, nil); err != nil {
		t.Fatalf("runAuto returned error: %v", err)
	}

	output := out.String()
	analyzeIdx := strings.Index(output, "Step: analyze")
	specIdx := strings.Index(output, "Step: spec")
	branchIdx := strings.Index(output, "Step: branch")
	convertIdx := strings.Index(output, "Step: convert")

	if analyzeIdx == -1 || specIdx == -1 || branchIdx == -1 || convertIdx == -1 {
		t.Fatalf("missing expected step sequence in output: %q", output)
	}
	if !(analyzeIdx < specIdx && specIdx < branchIdx && branchIdx < convertIdx) {
		t.Fatalf("unexpected step order, got output: %q", output)
	}
}

func TestRunAuto_DryRunSkipCIFlagSkipsCIStepWithoutWarning(t *testing.T) {
	chdirTemp(t)

	reportPath := filepath.Join(".", "report.md")
	if err := os.WriteFile(reportPath, []byte("# Report\n"), 0644); err != nil {
		t.Fatalf("write report: %v", err)
	}

	cmd, out := newAutoTestCommand(t)
	if err := cmd.Flags().Set("dry-run", "true"); err != nil {
		t.Fatalf("set dry-run flag: %v", err)
	}
	if err := cmd.Flags().Set("report", reportPath); err != nil {
		t.Fatalf("set report flag: %v", err)
	}
	if err := cmd.Flags().Set("skip-ci", "true"); err != nil {
		t.Fatalf("set skip-ci flag: %v", err)
	}

	var errOut bytes.Buffer
	cmd.SetErr(&errOut)

	if err := runAuto(cmd, nil); err != nil {
		t.Fatalf("runAuto returned error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Skipping CI step (--skip-ci)") {
		t.Fatalf("expected skip-ci message in output, got %q", output)
	}
	if strings.Contains(output, "Would push branch") {
		t.Fatalf("skip-ci should skip push/create in dry-run output, got %q", output)
	}
	if errOut.Len() > 0 {
		t.Fatalf("expected no stderr warning for --skip-ci, got %q", errOut.String())
	}
}

func TestRunAuto_DryRunSkipPRAliasWarnsAndSkipsCI(t *testing.T) {
	chdirTemp(t)

	reportPath := filepath.Join(".", "report.md")
	if err := os.WriteFile(reportPath, []byte("# Report\n"), 0644); err != nil {
		t.Fatalf("write report: %v", err)
	}

	cmd, out := newAutoTestCommand(t)
	if err := cmd.Flags().Set("dry-run", "true"); err != nil {
		t.Fatalf("set dry-run flag: %v", err)
	}
	if err := cmd.Flags().Set("report", reportPath); err != nil {
		t.Fatalf("set report flag: %v", err)
	}
	if err := cmd.Flags().Set("skip-pr", "true"); err != nil {
		t.Fatalf("set skip-pr flag: %v", err)
	}

	var errOut bytes.Buffer
	cmd.SetErr(&errOut)

	if err := runAuto(cmd, nil); err != nil {
		t.Fatalf("runAuto returned error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Skipping CI step (--skip-ci)") {
		t.Fatalf("expected skip-ci message in output, got %q", output)
	}
	if strings.Contains(output, "Would push branch") {
		t.Fatalf("skip-pr alias should skip push/create in dry-run output, got %q", output)
	}

	warning := errOut.String()
	if !strings.Contains(warning, "--skip-pr is deprecated; use --skip-ci") {
		t.Fatalf("expected skip-pr deprecation warning, got %q", warning)
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
			jr := autoFailureResult(autoEntryModeReportDiscovery, false, "failed", "failed", tt.failure, tt.resumable, compound.StepValidate)
			err := outputAutoJSON(&out, jr)
			if err != nil {
				t.Fatalf("outputAutoJSON returned error: %v", err)
			}

			assertAutoJSONContractV2(t, out.Bytes())

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
