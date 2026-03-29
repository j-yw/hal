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

func TestRunPRDAuditFn_LegacyAutoPRDMigrationIssues(t *testing.T) {
	tests := []struct {
		name               string
		setup              func(t *testing.T, halDir string)
		wantMigrationIssue bool
		wantIssueSubstr    string
	}{
		{
			name: "reports auto-prd.json as migration issue",
			setup: func(t *testing.T, halDir string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(halDir, template.AutoPRDFile), []byte(`{"branchName":"compound/y","tasks":[{"id":"T-001","passes":false}]}`), 0644); err != nil {
					t.Fatalf("write auto-prd.json: %v", err)
				}
			},
			wantMigrationIssue: true,
			wantIssueSubstr:    filepath.Join(template.HalDir, template.AutoPRDFile),
		},
		{
			name: "reports legacy backup artifacts as migration issue",
			setup: func(t *testing.T, halDir string) {
				t.Helper()
				legacy := filepath.Join(halDir, "auto-prd.legacy-20260329-120000.json")
				if err := os.WriteFile(legacy, []byte(`{"branchName":"compound/y"}`), 0644); err != nil {
					t.Fatalf("write legacy auto-prd backup: %v", err)
				}
			},
			wantMigrationIssue: true,
			wantIssueSubstr:    filepath.Join(template.HalDir, "auto-prd.legacy-20260329-120000.json"),
		},
		{
			name:               "does not report migration issue when legacy artifacts are absent",
			wantMigrationIssue: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			halDir := filepath.Join(dir, template.HalDir)
			if err := os.MkdirAll(halDir, 0755); err != nil {
				t.Fatalf("mkdir hal dir: %v", err)
			}

			if err := os.WriteFile(filepath.Join(halDir, template.PRDFile), []byte(`{"branchName":"hal/x","userStories":[{"id":"US-001","passes":false}]}`), 0644); err != nil {
				t.Fatalf("write prd.json: %v", err)
			}

			if tt.setup != nil {
				tt.setup(t, halDir)
			}

			var buf bytes.Buffer
			if err := runPRDAuditFn(dir, true, &buf); err != nil {
				t.Fatalf("runPRDAuditFn() error = %v", err)
			}

			var result PRDAuditResult
			if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
				t.Fatalf("JSON unmarshal error: %v\n%s", err, buf.String())
			}

			hasMigrationIssue := false
			hasExpectedPath := tt.wantIssueSubstr == ""
			for _, issue := range result.Issues {
				if strings.Contains(issue, "migration issue") {
					hasMigrationIssue = true
				}
				if tt.wantIssueSubstr != "" && strings.Contains(issue, tt.wantIssueSubstr) {
					hasExpectedPath = true
				}
				if strings.Contains(issue, "manual and auto PRDs may conflict") {
					t.Fatalf("legacy conflict wording should not appear: %v", result.Issues)
				}
			}

			if hasMigrationIssue != tt.wantMigrationIssue {
				t.Fatalf("migration issue presence = %v, want %v (issues=%v)", hasMigrationIssue, tt.wantMigrationIssue, result.Issues)
			}
			if !hasExpectedPath {
				t.Fatalf("expected issue to mention %q, issues: %v", tt.wantIssueSubstr, result.Issues)
			}

			if tt.wantMigrationIssue && result.OK {
				t.Fatalf("result should not be OK when migration issues exist: %+v", result)
			}
			if !tt.wantMigrationIssue && !result.OK {
				t.Fatalf("result should be OK when no migration issues exist: %+v", result)
			}
		})
	}
}

func TestRunPRDAuditFn_NoHalDir(t *testing.T) {
	dir := t.TempDir()
	// No .hal/ at all

	var buf bytes.Buffer
	if err := runPRDAuditFn(dir, true, &buf); err != nil {
		t.Fatalf("runPRDAuditFn() error = %v", err)
	}

	var result PRDAuditResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON unmarshal error: %v", err)
	}

	if result.OK {
		t.Fatal("should not be OK with no .hal/")
	}
	if result.JSONExists {
		t.Fatal("jsonExists should be false")
	}
	if result.MarkdownExists {
		t.Fatal("markdownExists should be false")
	}
}
