package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func newAutoTestCommand(t *testing.T) (*cobra.Command, *bytes.Buffer) {
	t.Helper()

	cmd := &cobra.Command{Use: "auto"}
	cmd.Flags().Bool("dry-run", false, "")
	cmd.Flags().Bool("resume", false, "")
	cmd.Flags().Bool("no-ci", false, "")
	cmd.Flags().Bool("no-review", false, "")
	cmd.Flags().String("mode", "", "")
	cmd.Flags().Int("review-streak", 0, "")
	cmd.Flags().Int("review-max", 0, "")
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

func TestAutoCommand_HelpDescribesSourcePriority(t *testing.T) {
	if !strings.Contains(autoCmd.Long, "Source selection (when not resuming)") {
		t.Fatalf("auto help should describe source selection behavior: %q", autoCmd.Long)
	}
	if !strings.Contains(autoCmd.Long, "auto.sourcePriority") {
		t.Fatalf("auto help should mention auto.sourcePriority config: %q", autoCmd.Long)
	}
	if !strings.Contains(autoCmd.Long, "Convert mode policy") {
		t.Fatalf("auto help should describe convert mode policy: %q", autoCmd.Long)
	}
	if !strings.Contains(autoCmd.Long, "--report report.md") {
		t.Fatalf("auto examples should include --report usage: %q", autoCmd.Long)
	}
}

func TestAutoCommand_ExposesOnlySinglePipelineRuntimeFlags(t *testing.T) {
	expectedFlags := map[string]struct{}{
		"base":          {},
		"dry-run":       {},
		"engine":        {},
		"json":          {},
		"mode":          {},
		"no-ci":         {},
		"no-review":     {},
		"report":        {},
		"resume":        {},
		"review-max":    {},
		"review-streak": {},
	}

	gotFlags := map[string]struct{}{}
	autoCmd.LocalFlags().VisitAll(func(flag *pflag.Flag) {
		gotFlags[flag.Name] = struct{}{}
	})

	for name := range expectedFlags {
		if _, ok := gotFlags[name]; !ok {
			t.Fatalf("auto command missing expected runtime flag %q", name)
		}
	}

	for name := range gotFlags {
		if name == "help" {
			continue
		}
		if _, ok := expectedFlags[name]; !ok {
			t.Fatalf("auto command exposes unexpected runtime flag %q; single-pipeline flag set should stay fixed", name)
		}
	}

	legacyDualModeFlags := []string{"manual", "prd", "explode", "loop", "pr", "auto-prd", "from-step", "start-step"}
	for _, legacyFlag := range legacyDualModeFlags {
		if autoCmd.LocalFlags().Lookup(legacyFlag) != nil {
			t.Fatalf("legacy dual-mode runtime flag %q should not be exposed", legacyFlag)
		}
	}
}

func TestBuildAutoHeaderContext(t *testing.T) {
	tests := []struct {
		name                 string
		resume               bool
		entryMode            autoEntryMode
		autoDiscoveredSource bool
		convertMode          string
		want                 string
	}{
		{
			name:        "resume flow",
			resume:      true,
			entryMode:   autoEntryModeMarkdownPath,
			convertMode: compound.AutoConvertModeGranular,
			want:        "auto pipeline · resume from saved state · convert mode: granular",
		},
		{
			name:                 "auto discovered markdown source",
			entryMode:            autoEntryModeMarkdownPath,
			autoDiscoveredSource: true,
			convertMode:          compound.AutoConvertModeStandard,
			want:                 "auto pipeline · entry: markdown PRD (auto-discovered) · convert mode: standard",
		},
		{
			name:        "explicit markdown source",
			entryMode:   autoEntryModeMarkdownPath,
			convertMode: compound.AutoConvertModeStandard,
			want:        "auto pipeline · entry: markdown PRD · convert mode: standard",
		},
		{
			name:        "report discovery source",
			entryMode:   autoEntryModeReportDiscovery,
			convertMode: compound.AutoConvertModeGranular,
			want:        "auto pipeline · entry: report discovery · convert mode: granular",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildAutoHeaderContext(tt.resume, tt.entryMode, tt.autoDiscoveredSource, tt.convertMode)
			if got != tt.want {
				t.Fatalf("buildAutoHeaderContext() = %q, want %q", got, tt.want)
			}
		})
	}
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

func TestRunAuto_DryRunHeaderUsesAutoPipelineLabel(t *testing.T) {
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
	if strings.Contains(output, "compound pipeline") {
		t.Fatalf("header should not mention compound pipeline: %q", output)
	}
	if !strings.Contains(output, "auto pipeline") {
		t.Fatalf("header should mention auto pipeline: %q", output)
	}
	if !strings.Contains(output, "entry: report discovery") || !strings.Contains(output, "convert mode:") || !strings.Contains(output, "granular") {
		t.Fatalf("header should describe report entry + granular convert mode: %q", output)
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
	wantErr := "no auto source found (sourcePriority=report_first): looked for latest report in auto.reportsDir, then newest .hal/prd-*.md; provide 'hal auto <prd-path>' or '--report <path>'"
	if result.Error != wantErr {
		t.Fatalf("result.Error = %q, want %q", result.Error, wantErr)
	}
	if result.NextAction == nil {
		t.Fatal("result.NextAction should not be nil")
	}
	if result.NextAction.ID != "run_auto" {
		t.Fatalf("result.NextAction.ID = %q, want run_auto", result.NextAction.ID)
	}
	if !strings.Contains(result.NextAction.Command, "<prd-path>") || !strings.Contains(result.NextAction.Command, "--report <path>") {
		t.Fatalf("result.NextAction.Command = %q, want markdown/report guidance", result.NextAction.Command)
	}
	if strings.Contains(out.String(), "No reports found.") {
		t.Fatalf("stdout should not include legacy text-mode message: %q", out.String())
	}
	if strings.Contains(out.String(), "compound pipeline") {
		t.Fatalf("stdout should not include command header: %q", out.String())
	}
}

func TestRunAuto_NoSourceErrorsAreDeterministicForBothPriorities(t *testing.T) {
	tests := []struct {
		name        string
		configYAML  string
		wantErrText string
	}{
		{
			name:        "report_first default",
			configYAML:  "",
			wantErrText: "no auto source found (sourcePriority=report_first): looked for latest report in auto.reportsDir, then newest .hal/prd-*.md; provide 'hal auto <prd-path>' or '--report <path>'",
		},
		{
			name: "markdown_first configured",
			configYAML: `auto:
  sourcePriority: markdown_first
`,
			wantErrText: "no auto source found (sourcePriority=markdown_first): looked for newest .hal/prd-*.md, then latest report in auto.reportsDir; provide 'hal auto <prd-path>' or '--report <path>'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chdirTemp(t)
			if strings.TrimSpace(tt.configYAML) != "" {
				if err := os.MkdirAll(template.HalDir, 0755); err != nil {
					t.Fatalf("mkdir .hal: %v", err)
				}
				if err := os.WriteFile(filepath.Join(template.HalDir, template.ConfigFile), []byte(tt.configYAML), 0644); err != nil {
					t.Fatalf("write config: %v", err)
				}
			}

			cmd, _ := newAutoTestCommand(t)
			err := runAuto(cmd, nil)
			if err == nil {
				t.Fatal("expected no-source error, got nil")
			}
			if err.Error() != tt.wantErrText {
				t.Fatalf("error = %q, want %q", err.Error(), tt.wantErrText)
			}
		})
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

func TestRunAuto_JSONResumeEntryModeUsesSavedMarkdownPath(t *testing.T) {
	chdirTemp(t)

	halDir := template.HalDir
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	statePath := filepath.Join(halDir, template.AutoStateFile)
	if err := os.WriteFile(statePath, []byte(`{"step":"done","sourceMarkdown":"./feature.md"}`), 0644); err != nil {
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
	if result.EntryMode != string(autoEntryModeMarkdownPath) {
		t.Fatalf("result.EntryMode = %q, want %q", result.EntryMode, autoEntryModeMarkdownPath)
	}
	if result.Steps.Analyze.Status != autoStepStatusSkipped {
		t.Fatalf("result.Steps.Analyze.Status = %q, want %q", result.Steps.Analyze.Status, autoStepStatusSkipped)
	}
	if result.Steps.Spec.Status != autoStepStatusSkipped {
		t.Fatalf("result.Steps.Spec.Status = %q, want %q", result.Steps.Spec.Status, autoStepStatusSkipped)
	}
	if result.Steps.Convert.Reason != compound.AutoConvertModeGranular {
		t.Fatalf("result.Steps.Convert.Reason = %q, want %q", result.Steps.Convert.Reason, compound.AutoConvertModeGranular)
	}
}

func TestRunAuto_JSONResumeEntryModeKeepsReportDiscoveryWhenAnalysisPresent(t *testing.T) {
	chdirTemp(t)

	halDir := template.HalDir
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	statePath := filepath.Join(halDir, template.AutoStateFile)
	if err := os.WriteFile(statePath, []byte(`{"step":"done","sourceMarkdown":".hal/prd-generated.md","analysis":{"priorityItem":"test"}}`), 0644); err != nil {
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
	if result.EntryMode != string(autoEntryModeReportDiscovery) {
		t.Fatalf("result.EntryMode = %q, want %q", result.EntryMode, autoEntryModeReportDiscovery)
	}
	if result.Steps.Analyze.Status != autoStepStatusCompleted {
		t.Fatalf("result.Steps.Analyze.Status = %q, want %q", result.Steps.Analyze.Status, autoStepStatusCompleted)
	}
	if result.Steps.Spec.Status != autoStepStatusCompleted {
		t.Fatalf("result.Steps.Spec.Status = %q, want %q", result.Steps.Spec.Status, autoStepStatusCompleted)
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
	if !strings.Contains(output, "entry: markdown PRD") || !strings.Contains(output, "convert mode:") || !strings.Contains(output, "standard") {
		t.Fatalf("expected markdown entry header with standard mode, got %q", output)
	}
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

func TestRunAuto_DryRunWithoutInputsUsesReportFirstByDefault(t *testing.T) {
	chdirTemp(t)

	if err := os.MkdirAll(filepath.Join(template.HalDir, "reports"), 0755); err != nil {
		t.Fatalf("mkdir reports dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(template.HalDir, "reports", "report.md"), []byte("# Report\n"), 0644); err != nil {
		t.Fatalf("write report: %v", err)
	}

	olderPRD := filepath.Join(template.HalDir, "prd-older.md")
	if err := os.WriteFile(olderPRD, []byte("# PRD: Older Source\n"), 0644); err != nil {
		t.Fatalf("write older prd: %v", err)
	}

	newerPRD := filepath.Join(template.HalDir, "prd-newer.md")
	if err := os.WriteFile(newerPRD, []byte("# PRD: Newer Preferred Source\n"), 0644); err != nil {
		t.Fatalf("write newer prd: %v", err)
	}

	olderTime := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	newerTime := time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(olderPRD, olderTime, olderTime); err != nil {
		t.Fatalf("chtimes older prd: %v", err)
	}
	if err := os.Chtimes(newerPRD, newerTime, newerTime); err != nil {
		t.Fatalf("chtimes newer prd: %v", err)
	}

	cmd, out := newAutoTestCommand(t)
	if err := cmd.Flags().Set("dry-run", "true"); err != nil {
		t.Fatalf("set dry-run flag: %v", err)
	}

	if err := runAuto(cmd, nil); err != nil {
		t.Fatalf("runAuto returned error: %v", err)
	}

	output := out.String()
	if strings.Contains(output, "Source markdown:") {
		t.Fatalf("default report_first discovery should not pick markdown when report exists, output=%q", output)
	}
	if !strings.Contains(output, "entry: report discovery") || !strings.Contains(output, "convert mode:") || !strings.Contains(output, "granular") {
		t.Fatalf("expected report entry header with granular mode, got %q", output)
	}
	if !strings.Contains(output, "Step: analyze") {
		t.Fatalf("report-first discovery should run analyze, output=%q", output)
	}
	if !strings.Contains(output, "Step: spec") {
		t.Fatalf("report-first discovery should run spec, output=%q", output)
	}
	if !strings.Contains(output, "Step: branch") {
		t.Fatalf("expected branch step in output, got %q", output)
	}
}

func TestRunAuto_DryRunWithoutInputsDiscoversNonMarkdownReport(t *testing.T) {
	chdirTemp(t)

	if err := os.MkdirAll(filepath.Join(template.HalDir, "reports"), 0755); err != nil {
		t.Fatalf("mkdir reports dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(template.HalDir, "reports", "report.txt"), []byte("priority: fix auto discovery\n"), 0644); err != nil {
		t.Fatalf("write report: %v", err)
	}

	cmd, out := newAutoTestCommand(t)
	if err := cmd.Flags().Set("dry-run", "true"); err != nil {
		t.Fatalf("set dry-run flag: %v", err)
	}

	if err := runAuto(cmd, nil); err != nil {
		t.Fatalf("runAuto returned error: %v", err)
	}

	output := out.String()
	if strings.Contains(output, "Source markdown:") {
		t.Fatalf("report-first discovery should not pick markdown when report exists, output=%q", output)
	}
	if !strings.Contains(output, "entry: report discovery") || !strings.Contains(output, "convert mode:") || !strings.Contains(output, "granular") {
		t.Fatalf("expected report entry header with granular mode, got %q", output)
	}
	if !strings.Contains(output, "Step: analyze") {
		t.Fatalf("report-first discovery should run analyze, output=%q", output)
	}
	if !strings.Contains(output, "Step: spec") {
		t.Fatalf("report-first discovery should run spec, output=%q", output)
	}
}

func TestRunAuto_DryRunWithoutInputsUsesMarkdownWhenPriorityConfigured(t *testing.T) {
	chdirTemp(t)

	if err := os.MkdirAll(filepath.Join(template.HalDir, "reports"), 0755); err != nil {
		t.Fatalf("mkdir reports dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(template.HalDir, "reports", "report.md"), []byte("# Report\n"), 0644); err != nil {
		t.Fatalf("write report: %v", err)
	}
	if err := os.WriteFile(filepath.Join(template.HalDir, template.ConfigFile), []byte("auto:\n  sourcePriority: markdown_first\n"), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	newerPRD := filepath.Join(template.HalDir, "prd-newer.md")
	if err := os.WriteFile(newerPRD, []byte("# PRD: Markdown Priority Source\n"), 0644); err != nil {
		t.Fatalf("write newer prd: %v", err)
	}

	cmd, out := newAutoTestCommand(t)
	if err := cmd.Flags().Set("dry-run", "true"); err != nil {
		t.Fatalf("set dry-run flag: %v", err)
	}

	if err := runAuto(cmd, nil); err != nil {
		t.Fatalf("runAuto returned error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "entry: markdown PRD (auto-discovered)") || !strings.Contains(output, "convert mode:") || !strings.Contains(output, "standard") {
		t.Fatalf("expected markdown-first entry header with standard mode, got %q", output)
	}
	if !strings.Contains(output, "Source markdown: "+newerPRD) {
		t.Fatalf("expected discovered markdown source %q in output, got %q", newerPRD, output)
	}
	if strings.Contains(output, "Step: analyze") {
		t.Fatalf("markdown-first discovery should skip analyze, output=%q", output)
	}
	if strings.Contains(output, "Step: spec") {
		t.Fatalf("markdown-first discovery should skip spec, output=%q", output)
	}
}

func TestRunAuto_JSONDryRunWithoutInputsPrefersNewestMarkdownPRD(t *testing.T) {
	chdirTemp(t)

	if err := os.MkdirAll(template.HalDir, 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(template.HalDir, "prd-auto.md"), []byte("# PRD: JSON Entry Source\n"), 0644); err != nil {
		t.Fatalf("write markdown: %v", err)
	}

	cmd, out := newAutoTestCommand(t)
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set json flag: %v", err)
	}
	if err := cmd.Flags().Set("dry-run", "true"); err != nil {
		t.Fatalf("set dry-run flag: %v", err)
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
	if result.EntryMode != string(autoEntryModeMarkdownPath) {
		t.Fatalf("result.EntryMode = %q, want %q", result.EntryMode, autoEntryModeMarkdownPath)
	}
	if result.Steps.Analyze.Status != autoStepStatusSkipped {
		t.Fatalf("result.Steps.Analyze.Status = %q, want %q", result.Steps.Analyze.Status, autoStepStatusSkipped)
	}
	if result.Steps.Spec.Status != autoStepStatusSkipped {
		t.Fatalf("result.Steps.Spec.Status = %q, want %q", result.Steps.Spec.Status, autoStepStatusSkipped)
	}
	if result.Steps.Convert.Reason != compound.AutoConvertModeStandard {
		t.Fatalf("result.Steps.Convert.Reason = %q, want %q", result.Steps.Convert.Reason, compound.AutoConvertModeStandard)
	}
}

func TestRunAuto_JSONDryRunReportEntryEmitsGranularConvertReason(t *testing.T) {
	chdirTemp(t)

	reportPath := filepath.Join(".", "report.md")
	if err := os.WriteFile(reportPath, []byte("# Report\n"), 0644); err != nil {
		t.Fatalf("write report: %v", err)
	}

	cmd, out := newAutoTestCommand(t)
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set json flag: %v", err)
	}
	if err := cmd.Flags().Set("dry-run", "true"); err != nil {
		t.Fatalf("set dry-run flag: %v", err)
	}
	if err := cmd.Flags().Set("report", reportPath); err != nil {
		t.Fatalf("set report flag: %v", err)
	}

	if err := runAuto(cmd, nil); err != nil {
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
	if result.Steps.Convert.Reason != compound.AutoConvertModeGranular {
		t.Fatalf("result.Steps.Convert.Reason = %q, want %q", result.Steps.Convert.Reason, compound.AutoConvertModeGranular)
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
	if !strings.Contains(output, "entry: report discovery") || !strings.Contains(output, "convert mode:") || !strings.Contains(output, "granular") {
		t.Fatalf("expected report entry header with granular mode, got %q", output)
	}
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

func TestRunAuto_DryRunNoCIFlagSkipsCIStep(t *testing.T) {
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
	if err := cmd.Flags().Set("no-ci", "true"); err != nil {
		t.Fatalf("set no-ci flag: %v", err)
	}

	if err := runAuto(cmd, nil); err != nil {
		t.Fatalf("runAuto returned error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Skipping CI step (--no-ci)") {
		t.Fatalf("expected no-ci message in output, got %q", output)
	}
	if strings.Contains(output, "Would push branch") {
		t.Fatalf("no-ci should skip push/create in dry-run output, got %q", output)
	}
}

func TestRunAuto_DryRunNoReviewSkipsReviewGate(t *testing.T) {
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
	if err := cmd.Flags().Set("no-review", "true"); err != nil {
		t.Fatalf("set no-review flag: %v", err)
	}

	if err := runAuto(cmd, nil); err != nil {
		t.Fatalf("runAuto returned error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Step: review") {
		t.Fatalf("expected review step in output, got %q", output)
	}
	if !strings.Contains(output, "Skipping review step") {
		t.Fatalf("expected review skip message in output, got %q", output)
	}
	if !strings.Contains(output, "Step: ci") {
		t.Fatalf("expected CI step after skipped review, got %q", output)
	}
}

func TestRunAuto_DryRunUsesConfigModeFast(t *testing.T) {
	chdirTemp(t)

	if err := os.MkdirAll(template.HalDir, 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	cfg := `auto:
  mode: fast
`
	if err := os.WriteFile(filepath.Join(template.HalDir, template.ConfigFile), []byte(cfg), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

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
	if !strings.Contains(output, "Mode: fast") {
		t.Fatalf("expected fast mode in output, got %q", output)
	}
	if !strings.Contains(output, "Skipping review step") {
		t.Fatalf("expected review skip in output, got %q", output)
	}
	if !strings.Contains(output, "Skipping CI step (--no-ci)") {
		t.Fatalf("expected CI skip in output, got %q", output)
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
			name:        "no source suggests markdown or report",
			failure:     autoFailureNoSource,
			resumable:   false,
			wantID:      "run_auto",
			wantCommand: "hal auto <prd-path> | hal auto --report <path>",
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
			jr := autoFailureResult(autoEntryModeReportDiscovery, false, "failed", "failed", tt.failure, tt.resumable, compound.StepValidate, compound.AutoConvertModeGranular)
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

func TestAutoFailurePolicySkipsAfterGate(t *testing.T) {
	jr := autoFailureResult(autoEntryModeReportDiscovery, false, "failed", "failed", autoFailurePipeline, false, compound.StepReport, compound.AutoConvertModeGranular)

	applyAutoFailurePolicySkips(&jr.Steps, compound.StepReport, true, true)
	applyAutoFailureCIState(&jr.Steps, compound.StepReport, &compound.CIState{Status: "skipped", Reason: "ci_disabled_by_policy"})

	if jr.Steps.Review.Status != autoStepStatusSkipped {
		t.Fatalf("review status = %q, want %q", jr.Steps.Review.Status, autoStepStatusSkipped)
	}
	if jr.Steps.Review.Reason != "skip_review_flag" {
		t.Fatalf("review reason = %q, want %q", jr.Steps.Review.Reason, "skip_review_flag")
	}
	if jr.Steps.CI.Status != autoStepStatusSkipped {
		t.Fatalf("ci status = %q, want %q", jr.Steps.CI.Status, autoStepStatusSkipped)
	}
	if jr.Steps.CI.Reason != "ci_disabled_by_policy" {
		t.Fatalf("ci reason = %q, want %q", jr.Steps.CI.Reason, "ci_disabled_by_policy")
	}
}
