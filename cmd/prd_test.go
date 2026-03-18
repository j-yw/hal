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

func TestRunPRDAuditFn_NoPRD(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)

	var buf bytes.Buffer
	if err := runPRDAuditFn(dir, false, &buf); err != nil {
		t.Fatalf("runPRDAuditFn() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "not found") {
		t.Fatalf("should report no PRD found\n%s", output)
	}
}

func TestRunPRDAuditFn_HealthyJSON(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)

	prd := `{"project":"test","branchName":"hal/feature","userStories":[{"id":"US-001","title":"First","passes":false}]}`
	os.WriteFile(filepath.Join(halDir, template.PRDFile), []byte(prd), 0644)

	var buf bytes.Buffer
	if err := runPRDAuditFn(dir, true, &buf); err != nil {
		t.Fatalf("runPRDAuditFn() error = %v", err)
	}

	var result PRDAuditResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON unmarshal error: %v\n%s", err, buf.String())
	}

	if !result.OK {
		t.Fatalf("should be OK, issues: %v", result.Issues)
	}
	if !result.JSONExists {
		t.Fatal("jsonExists should be true")
	}
	if result.PRDSummary == nil {
		t.Fatal("prd summary should not be nil")
	}
	if result.PRDSummary.TotalStories != 1 {
		t.Fatalf("totalStories = %d, want 1", result.PRDSummary.TotalStories)
	}
}

func TestRunPRDAuditFn_DriftDetected(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)

	// Both JSON and markdown exist
	os.WriteFile(filepath.Join(halDir, template.PRDFile), []byte(`{"branchName":"hal/x","userStories":[{"id":"US-001","passes":false}]}`), 0644)
	os.WriteFile(filepath.Join(halDir, "prd-feature.md"), []byte("# Feature"), 0644)

	var buf bytes.Buffer
	if err := runPRDAuditFn(dir, true, &buf); err != nil {
		t.Fatalf("runPRDAuditFn() error = %v", err)
	}

	var result PRDAuditResult
	json.Unmarshal(buf.Bytes(), &result)

	if result.OK {
		t.Fatal("should not be OK when both exist (drift)")
	}
	if !result.JSONExists || !result.MarkdownExists {
		t.Fatal("both should exist")
	}
	found := false
	for _, issue := range result.Issues {
		if strings.Contains(issue, "drift") {
			found = true
		}
	}
	if !found {
		t.Fatalf("should detect drift, issues: %v", result.Issues)
	}
}

func TestRunPRDAuditFn_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	os.WriteFile(filepath.Join(halDir, template.PRDFile), []byte("{broken"), 0644)

	var buf bytes.Buffer
	runPRDAuditFn(dir, true, &buf)

	var result PRDAuditResult
	json.Unmarshal(buf.Bytes(), &result)

	if result.OK {
		t.Fatal("should not be OK for invalid JSON")
	}
}

func TestPRDCmdHelp(t *testing.T) {
	if prdCmd.Use != "prd" {
		t.Fatalf("Use = %q, want %q", prdCmd.Use, "prd")
	}
	if prdAuditCmd.Short == "" {
		t.Fatal("audit Short is empty")
	}
	if !strings.Contains(prdAuditCmd.Example, "hal prd audit") {
		t.Fatalf("audit Example missing 'hal prd audit': %s", prdAuditCmd.Example)
	}
}

func TestRunPRDAuditFn_MissingBranchName(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)

	// PRD with no branchName
	prd := `{"project":"test","userStories":[{"id":"US-001","passes":false}]}`
	os.WriteFile(filepath.Join(halDir, template.PRDFile), []byte(prd), 0644)

	var buf bytes.Buffer
	runPRDAuditFn(dir, true, &buf)

	var result PRDAuditResult
	json.Unmarshal(buf.Bytes(), &result)

	if result.OK {
		t.Fatal("should not be OK when branchName is missing")
	}

	found := false
	for _, issue := range result.Issues {
		if strings.Contains(issue, "branchName") {
			found = true
		}
	}
	if !found {
		t.Fatalf("should detect missing branchName, issues: %v", result.Issues)
	}
}

func TestRunPRDAuditFn_MarkdownOnly(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)

	os.WriteFile(filepath.Join(halDir, "prd-feature.md"), []byte("# My Feature"), 0644)

	var buf bytes.Buffer
	runPRDAuditFn(dir, false, &buf)

	output := buf.String()
	if !strings.Contains(output, "Markdown PRD") && !strings.Contains(output, "✓") {
		t.Fatalf("should show markdown PRD found\n%s", output)
	}
}

func TestRunPRDAuditFn_AutoPRDConflict(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)

	// Both manual and auto PRD
	os.WriteFile(filepath.Join(halDir, template.PRDFile), []byte(`{"branchName":"hal/x","userStories":[{"id":"US-001","passes":false}]}`), 0644)
	os.WriteFile(filepath.Join(halDir, template.AutoPRDFile), []byte(`{"branchName":"compound/y","tasks":[{"id":"T-001","passes":false}]}`), 0644)

	var buf bytes.Buffer
	runPRDAuditFn(dir, true, &buf)

	var result PRDAuditResult
	json.Unmarshal(buf.Bytes(), &result)

	if result.OK {
		t.Fatal("should not be OK when both prd.json and auto-prd.json exist")
	}
	found := false
	for _, issue := range result.Issues {
		if strings.Contains(issue, "auto-prd.json") {
			found = true
		}
	}
	if !found {
		t.Fatalf("should detect auto-prd conflict, issues: %v", result.Issues)
	}
}
