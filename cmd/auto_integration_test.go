//go:build integration
// +build integration

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
