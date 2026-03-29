//go:build integration
// +build integration

package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/template"
)

func resetAutoFlagsForIntegrationTest() {
	if flag := autoCmd.Flags().Lookup("dry-run"); flag != nil {
		_ = flag.Value.Set("false")
		flag.Changed = false
	}
	if flag := autoCmd.Flags().Lookup("resume"); flag != nil {
		_ = flag.Value.Set("false")
		flag.Changed = false
	}
	if flag := autoCmd.Flags().Lookup("skip-ci"); flag != nil {
		_ = flag.Value.Set("false")
		flag.Changed = false
	}
	if flag := autoCmd.Flags().Lookup("skip-pr"); flag != nil {
		_ = flag.Value.Set("false")
		flag.Changed = false
	}
	if flag := autoCmd.Flags().Lookup("report"); flag != nil {
		_ = flag.Value.Set("")
		flag.Changed = false
	}
	if flag := autoCmd.Flags().Lookup("engine"); flag != nil {
		_ = flag.Value.Set("codex")
		flag.Changed = false
	}
	if flag := autoCmd.Flags().Lookup("base"); flag != nil {
		_ = flag.Value.Set("")
		flag.Changed = false
	}
	if flag := autoCmd.Flags().Lookup("json"); flag != nil {
		_ = flag.Value.Set("false")
		flag.Changed = false
	}

	autoDryRunFlag = false
	autoResumeFlag = false
	autoSkipCIFlag = false
	autoSkipPRFlag = false
	autoReportFlag = ""
	autoEngineFlag = "codex"
	autoBaseFlag = ""
	autoJSONFlag = false
}

func writeLegacyAutoStateFixture(t *testing.T, dir string, state map[string]any) {
	t.Helper()

	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}

	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal legacy state: %v", err)
	}

	statePath := filepath.Join(halDir, template.AutoStateFile)
	if err := os.WriteFile(statePath, data, 0644); err != nil {
		t.Fatalf("write auto-state fixture: %v", err)
	}
}

func TestAutoDryRunWithPositionalMarkdownInput(t *testing.T) {
	dir := t.TempDir()
	mdPath := filepath.Join(dir, "entry-prd.md")
	mdContent := "# PRD: Integration Auto Entry Path\n\n## Scope\n- verify positional markdown entry\n"
	if err := os.WriteFile(mdPath, []byte(mdContent), 0644); err != nil {
		t.Fatalf("write markdown fixture: %v", err)
	}

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(origDir)
	})

	root := Root()
	origOut := root.OutOrStdout()
	origErr := root.ErrOrStderr()
	origIn := root.InOrStdin()
	t.Cleanup(func() {
		root.SetOut(origOut)
		root.SetErr(origErr)
		root.SetIn(origIn)
		root.SetArgs(nil)
	})

	resetAutoFlagsForIntegrationTest()
	t.Cleanup(resetAutoFlagsForIntegrationTest)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"auto", "--dry-run", filepath.Base(mdPath)})

	if err := root.Execute(); err != nil {
		t.Fatalf("hal auto --dry-run failed: %v\nstderr: %s\nstdout: %s", err, stderr.String(), stdout.String())
	}

	output := stdout.String()
	if !strings.Contains(output, "Step: branch") {
		t.Fatalf("expected branch step in output, got %q", output)
	}
	if !strings.Contains(output, "Would create branch: hal/integration-auto-entry-path") {
		t.Fatalf("expected branch derived from positional markdown title, got %q", output)
	}
	if !strings.Contains(output, "Step: convert") {
		t.Fatalf("expected convert step in output, got %q", output)
	}
	if strings.Contains(output, "Step: analyze") {
		t.Fatalf("positional markdown input should skip analyze, output=%q", output)
	}
	if strings.Contains(output, "Step: spec") {
		t.Fatalf("positional markdown input should skip spec, output=%q", output)
	}
}

func TestAutoDryRunWithoutPositionalMarkdownInput(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.md")
	if err := os.WriteFile(reportPath, []byte("# Integration Report\n"), 0644); err != nil {
		t.Fatalf("write report fixture: %v", err)
	}

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(origDir)
	})

	root := Root()
	origOut := root.OutOrStdout()
	origErr := root.ErrOrStderr()
	origIn := root.InOrStdin()
	t.Cleanup(func() {
		root.SetOut(origOut)
		root.SetErr(origErr)
		root.SetIn(origIn)
		root.SetArgs(nil)
	})

	resetAutoFlagsForIntegrationTest()
	t.Cleanup(resetAutoFlagsForIntegrationTest)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"auto", "--dry-run", "--report", filepath.Base(reportPath)})

	if err := root.Execute(); err != nil {
		t.Fatalf("hal auto --dry-run failed: %v\nstderr: %s\nstdout: %s", err, stderr.String(), stdout.String())
	}

	output := stdout.String()
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

func TestAutoDryRunSkipPRAliasCompatibility(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.md")
	if err := os.WriteFile(reportPath, []byte("# Integration Report\n"), 0644); err != nil {
		t.Fatalf("write report fixture: %v", err)
	}

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(origDir)
	})

	root := Root()
	origOut := root.OutOrStdout()
	origErr := root.ErrOrStderr()
	origIn := root.InOrStdin()
	t.Cleanup(func() {
		root.SetOut(origOut)
		root.SetErr(origErr)
		root.SetIn(origIn)
		root.SetArgs(nil)
	})

	resetAutoFlagsForIntegrationTest()
	t.Cleanup(resetAutoFlagsForIntegrationTest)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"auto", "--dry-run", "--report", filepath.Base(reportPath), "--skip-pr"})

	if err := root.Execute(); err != nil {
		t.Fatalf("hal auto --dry-run --skip-pr failed: %v\nstderr: %s\nstdout: %s", err, stderr.String(), stdout.String())
	}

	output := stdout.String()
	if !strings.Contains(output, "Skipping CI step (--skip-ci)") {
		t.Fatalf("expected CI skip message in output, got %q", output)
	}
	if strings.Contains(output, "Would push branch") {
		t.Fatalf("skip-pr alias should map to skip-ci behavior, got %q", output)
	}

	warnings := stderr.String()
	if !strings.Contains(warnings, "--skip-pr is deprecated; use --skip-ci") {
		t.Fatalf("expected skip-pr deprecation warning, got %q", warnings)
	}
}

func TestAutoResumeDryRunMapsLegacyStateSteps(t *testing.T) {
	tests := []struct {
		name         string
		legacyStep   string
		normalized   string
		legacyFields map[string]any
	}{
		{
			name:       "maps prd to spec",
			legacyStep: "prd",
			normalized: "spec",
			legacyFields: map[string]any{
				"analysis": map[string]any{
					"priorityItem":       "Legacy priority",
					"description":        "Legacy analysis description",
					"rationale":          "Legacy rationale",
					"acceptanceCriteria": []string{"Typecheck passes"},
					"estimatedTasks":     1,
					"branchName":         "legacy-resume-mapping",
				},
			},
		},
		{
			name:       "maps explode to convert",
			legacyStep: "explode",
			normalized: "convert",
			legacyFields: map[string]any{
				"sourceMarkdown": "legacy-prd.md",
			},
		},
		{
			name:         "maps loop to run",
			legacyStep:   "loop",
			normalized:   "run",
			legacyFields: map[string]any{},
		},
		{
			name:         "maps pr to ci",
			legacyStep:   "pr",
			normalized:   "ci",
			legacyFields: map[string]any{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			state := map[string]any{
				"step":       tt.legacyStep,
				"branchName": "hal/legacy-resume-mapping",
				"startedAt":  "2026-03-29T00:00:00Z",
			}
			for k, v := range tt.legacyFields {
				state[k] = v
			}
			writeLegacyAutoStateFixture(t, dir, state)

			origDir, err := os.Getwd()
			if err != nil {
				t.Fatalf("getwd: %v", err)
			}
			if err := os.Chdir(dir); err != nil {
				t.Fatalf("chdir temp dir: %v", err)
			}
			t.Cleanup(func() {
				_ = os.Chdir(origDir)
			})

			root := Root()
			origOut := root.OutOrStdout()
			origErr := root.ErrOrStderr()
			origIn := root.InOrStdin()
			t.Cleanup(func() {
				root.SetOut(origOut)
				root.SetErr(origErr)
				root.SetIn(origIn)
				root.SetArgs(nil)
			})

			resetAutoFlagsForIntegrationTest()
			t.Cleanup(resetAutoFlagsForIntegrationTest)

			var stdout bytes.Buffer
			var stderr bytes.Buffer
			root.SetOut(&stdout)
			root.SetErr(&stderr)
			root.SetArgs([]string{"auto", "--resume", "--dry-run"})

			if err := root.Execute(); err != nil {
				t.Fatalf("hal auto --resume --dry-run failed: %v\nstderr: %s\nstdout: %s", err, stderr.String(), stdout.String())
			}

			output := stdout.String()
			if !strings.Contains(output, "Resuming from step: "+tt.normalized) {
				t.Fatalf("expected normalized resume step %q in output, got %q", tt.normalized, output)
			}
			if strings.Contains(output, "Resuming from step: "+tt.legacyStep) {
				t.Fatalf("unexpected legacy resume step %q in output %q", tt.legacyStep, output)
			}
			if !strings.Contains(output, "Step: "+tt.normalized) {
				t.Fatalf("expected execution to continue at normalized step %q, got %q", tt.normalized, output)
			}
		})
	}
}
