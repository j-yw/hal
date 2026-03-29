package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/ci"
	"github.com/jywlabs/hal/internal/skills"
	"github.com/jywlabs/hal/internal/template"
)

func setupHalDir(t *testing.T, dir string) string {
	t.Helper()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Create config.yaml
	if err := os.WriteFile(filepath.Join(halDir, template.ConfigFile), []byte("engine: pi\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Create prompt.md
	if err := os.WriteFile(filepath.Join(halDir, template.PromptFile), []byte("# Agent Instructions\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Create progress.txt
	if err := os.WriteFile(filepath.Join(halDir, template.ProgressFile), []byte("## Codebase Patterns\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return halDir
}

func installSkills(t *testing.T, dir string) {
	t.Helper()
	halDir := filepath.Join(dir, template.HalDir)
	skillsDir := filepath.Join(halDir, "skills")
	if err := os.MkdirAll(skillsDir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range skills.ManagedSkillNames {
		skillPath := filepath.Join(skillsDir, name)
		if err := os.MkdirAll(skillPath, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(skillPath, "SKILL.md"), []byte("# "+name), 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func installCommands(t *testing.T, dir string) {
	t.Helper()
	halDir := filepath.Join(dir, template.HalDir)
	commandsDir := filepath.Join(halDir, template.CommandsDir)
	if err := os.MkdirAll(commandsDir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range skills.CommandNames {
		if err := os.WriteFile(filepath.Join(commandsDir, name+".md"), []byte("# "+name), 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRun_NoHalDir(t *testing.T) {
	dir := t.TempDir()

	result := Run(Options{Dir: dir})

	if result.ContractVersion != ContractVersion {
		t.Fatalf("contractVersion = %d, want %d", result.ContractVersion, ContractVersion)
	}
	if result.OverallStatus != StatusFail {
		t.Fatalf("overallStatus = %q, want %q", result.OverallStatus, StatusFail)
	}
	if len(result.Failures) == 0 || result.Failures[0] != "hal_dir" {
		t.Fatalf("failures = %v, want [hal_dir]", result.Failures)
	}
}

func TestRun_HealthyNonCodexRepo(t *testing.T) {
	dir := t.TempDir()
	// Create .git
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	setupHalDir(t, dir)
	installSkills(t, dir)
	installCommands(t, dir)

	result := Run(Options{Dir: dir, Engine: "pi"})

	if result.OverallStatus != StatusPass {
		t.Fatalf("overallStatus = %q, want %q\nchecks: %+v", result.OverallStatus, StatusPass, result.Checks)
	}

	// Codex links should be skipped for pi engine
	found := false
	for _, c := range result.Checks {
		if c.ID == "codex_global_links" {
			found = true
			if c.Status != StatusSkip {
				t.Fatalf("codex_global_links status = %q, want %q", c.Status, StatusSkip)
			}
		}
	}
	if !found {
		t.Fatal("codex_global_links check not found")
	}
}

func TestRun_MissingSkills(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	setupHalDir(t, dir)
	installCommands(t, dir)
	// Don't install skills

	result := Run(Options{Dir: dir, Engine: "pi"})

	if result.OverallStatus != StatusFail {
		t.Fatalf("overallStatus = %q, want %q", result.OverallStatus, StatusFail)
	}

	found := false
	for _, f := range result.Failures {
		if f == "hal_skills" {
			found = true
		}
	}
	if !found {
		t.Fatalf("failures = %v, want hal_skills in list", result.Failures)
	}
}

func TestRun_MissingCommands(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	setupHalDir(t, dir)
	installSkills(t, dir)
	// Don't install commands

	result := Run(Options{Dir: dir, Engine: "pi"})

	if result.OverallStatus != StatusFail {
		t.Fatalf("overallStatus = %q, want %q", result.OverallStatus, StatusFail)
	}
}

func TestRun_NoGitRepo(t *testing.T) {
	dir := t.TempDir()
	setupHalDir(t, dir)
	installSkills(t, dir)
	installCommands(t, dir)

	result := Run(Options{Dir: dir, Engine: "pi"})

	// No .git should warn, not fail
	found := false
	for _, c := range result.Checks {
		if c.ID == "git_repo" {
			found = true
			if c.Status != StatusWarn {
				t.Fatalf("git_repo status = %q, want %q", c.Status, StatusWarn)
			}
		}
	}
	if !found {
		t.Fatal("git_repo check not found")
	}
}

func TestRun_EngineAwareCodexSkip(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	setupHalDir(t, dir)
	installSkills(t, dir)
	installCommands(t, dir)

	for _, eng := range []string{"pi", "claude"} {
		result := Run(Options{Dir: dir, Engine: eng})

		found := false
		for _, c := range result.Checks {
			if c.ID == "codex_global_links" {
				found = true
				if c.Status != StatusSkip {
					t.Fatalf("engine=%s: codex_global_links status = %q, want %q", eng, c.Status, StatusSkip)
				}
			}
		}
		if !found {
			t.Fatalf("engine=%s: codex_global_links check not found", eng)
		}
	}
}

func TestDoctorResult_JSONRoundTrip(t *testing.T) {
	original := DoctorResult{
		ContractVersion: ContractVersion,
		OverallStatus:   StatusPass,
		Checks: []Check{
			{ID: "git_repo", Status: StatusPass, Severity: SeverityInfo, RemediationID: RemediationNone, Message: "Git repository detected."},
		},
		Failures: []string{},
		Warnings: []string{},
		Summary:  "Hal is ready to use.",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded DoctorResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if decoded.ContractVersion != original.ContractVersion {
		t.Fatalf("contractVersion = %d, want %d", decoded.ContractVersion, original.ContractVersion)
	}
	if decoded.OverallStatus != original.OverallStatus {
		t.Fatalf("overallStatus = %q, want %q", decoded.OverallStatus, original.OverallStatus)
	}
	if len(decoded.Checks) != len(original.Checks) {
		t.Fatalf("checks len = %d, want %d", len(decoded.Checks), len(original.Checks))
	}
}

func TestRun_MissingConfigYAML(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	// No config.yaml
	installSkills(t, dir)
	installCommands(t, dir)

	result := Run(Options{Dir: dir, Engine: "pi"})

	found := false
	for _, c := range result.Checks {
		if c.ID == "config_yaml" {
			found = true
			if c.Status != StatusWarn {
				t.Fatalf("config_yaml status = %q, want %q", c.Status, StatusWarn)
			}
		}
	}
	if !found {
		t.Fatal("config_yaml check not found")
	}
}

func TestRun_LegacyDebrisDetected(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	setupHalDir(t, dir)
	installSkills(t, dir)
	installCommands(t, dir)

	// Create legacy .goralph directory
	os.MkdirAll(filepath.Join(dir, ".goralph"), 0755)
	// Create deprecated ralph skill link
	os.MkdirAll(filepath.Join(dir, ".claude", "skills"), 0755)
	os.Symlink("../../.hal/skills/hal", filepath.Join(dir, ".claude", "skills", "ralph"))

	result := Run(Options{Dir: dir, Engine: "pi"})

	found := false
	for _, c := range result.Checks {
		if c.ID == "legacy_debris" {
			found = true
			if c.Status != StatusWarn {
				t.Fatalf("legacy_debris status = %q, want %q", c.Status, StatusWarn)
			}
		}
	}
	if !found {
		t.Fatal("legacy_debris check not found")
	}
}

func TestRun_NoLegacyDebris(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	setupHalDir(t, dir)
	installSkills(t, dir)
	installCommands(t, dir)

	result := Run(Options{Dir: dir, Engine: "pi"})

	for _, c := range result.Checks {
		if c.ID == "legacy_debris" {
			if c.Status != StatusPass {
				t.Fatalf("legacy_debris status = %q, want %q (no debris present)", c.Status, StatusPass)
			}
			return
		}
	}
	t.Fatal("legacy_debris check not found")
}

func TestRun_PrimaryRemediation(t *testing.T) {
	dir := t.TempDir()
	// No .hal dir — should give hal init as primary remediation

	result := Run(Options{Dir: dir})

	if result.PrimaryRemediation == nil {
		t.Fatal("primaryRemediation should not be nil when there are failures")
	}
	if result.PrimaryRemediation.Command != "hal init" {
		t.Fatalf("primaryRemediation.command = %q, want %q", result.PrimaryRemediation.Command, "hal init")
	}
	if !result.PrimaryRemediation.Safe {
		t.Fatal("primaryRemediation.safe should be true for hal init")
	}
}

func TestRun_NoPrimaryRemediationWhenHealthy(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	setupHalDir(t, dir)
	installSkills(t, dir)
	installCommands(t, dir)

	result := Run(Options{Dir: dir, Engine: "pi"})

	if result.OverallStatus != StatusPass {
		t.Fatalf("overallStatus = %q, want %q", result.OverallStatus, StatusPass)
	}
	if result.PrimaryRemediation != nil {
		t.Fatalf("primaryRemediation should be nil when healthy, got %+v", result.PrimaryRemediation)
	}
}

func TestRun_LegacyDebrisRemediationIsCleanup(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	setupHalDir(t, dir)
	installSkills(t, dir)
	installCommands(t, dir)
	// Add legacy debris
	os.MkdirAll(filepath.Join(dir, ".goralph"), 0755)

	result := Run(Options{Dir: dir, Engine: "pi"})

	if result.PrimaryRemediation == nil {
		t.Fatal("primaryRemediation should not be nil")
	}
	if result.PrimaryRemediation.Command != "hal cleanup" {
		t.Fatalf("primaryRemediation.command = %q, want %q", result.PrimaryRemediation.Command, "hal cleanup")
	}
}

func TestRun_BrokenSkillLinksDetected(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	setupHalDir(t, dir)
	installSkills(t, dir)
	installCommands(t, dir)

	// Create a broken symlink in .claude/skills/
	claudeSkills := filepath.Join(dir, ".claude", "skills")
	os.MkdirAll(claudeSkills, 0755)
	os.Symlink("/nonexistent/path/that/does/not/exist", filepath.Join(claudeSkills, "broken-link"))

	result := Run(Options{Dir: dir, Engine: "pi"})

	found := false
	for _, c := range result.Checks {
		if c.ID == "broken_skill_links" {
			found = true
			if c.Status != StatusWarn {
				t.Fatalf("broken_skill_links status = %q, want %q", c.Status, StatusWarn)
			}
		}
	}
	if !found {
		t.Fatal("broken_skill_links check not found")
	}
}

func TestRun_NoBrokenSkillLinks(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	setupHalDir(t, dir)
	installSkills(t, dir)
	installCommands(t, dir)

	result := Run(Options{Dir: dir, Engine: "pi"})

	for _, c := range result.Checks {
		if c.ID == "broken_skill_links" {
			if c.Status != StatusPass {
				t.Fatalf("broken_skill_links status = %q, want %q", c.Status, StatusPass)
			}
			return
		}
	}
	t.Fatal("broken_skill_links check not found")
}

func TestRun_InvalidYAMLConfig(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	// Write invalid YAML
	os.WriteFile(filepath.Join(halDir, template.ConfigFile), []byte("engine: [\ninvalid yaml"), 0644)
	installSkills(t, dir)
	installCommands(t, dir)

	result := Run(Options{Dir: dir, Engine: "pi"})

	found := false
	for _, c := range result.Checks {
		if c.ID == "config_yaml" {
			found = true
			if c.Status != StatusFail {
				t.Fatalf("config_yaml status = %q, want %q for invalid YAML", c.Status, StatusFail)
			}
			if c.Remediation == nil {
				t.Fatal("config_yaml should have remediation for invalid YAML")
			}
		}
	}
	if !found {
		t.Fatal("config_yaml check not found")
	}
}

func TestRun_MissingPromptMD(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	halDir := setupHalDir(t, dir)
	installSkills(t, dir)
	installCommands(t, dir)
	// Remove prompt.md created by setupHalDir
	os.Remove(filepath.Join(halDir, template.PromptFile))

	result := Run(Options{Dir: dir, Engine: "pi"})

	found := false
	for _, c := range result.Checks {
		if c.ID == "prompt_md" {
			found = true
			if c.Status != StatusWarn {
				t.Fatalf("prompt_md status = %q, want %q", c.Status, StatusWarn)
			}
		}
	}
	if !found {
		t.Fatal("prompt_md check not found")
	}
}

func TestRun_EmptyPromptMD(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	halDir := setupHalDir(t, dir)
	installSkills(t, dir)
	installCommands(t, dir)
	os.WriteFile(filepath.Join(halDir, "prompt.md"), []byte("  \n  "), 0644)

	result := Run(Options{Dir: dir, Engine: "pi"})

	for _, c := range result.Checks {
		if c.ID == "prompt_md" {
			if c.Status != StatusWarn {
				t.Fatalf("prompt_md status = %q, want %q for empty prompt", c.Status, StatusWarn)
			}
			return
		}
	}
	t.Fatal("prompt_md check not found")
}

func TestRun_ValidPromptMD(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	halDir := setupHalDir(t, dir)
	installSkills(t, dir)
	installCommands(t, dir)
	os.WriteFile(filepath.Join(halDir, "prompt.md"), []byte("# Agent Instructions\nDo good work."), 0644)

	result := Run(Options{Dir: dir, Engine: "pi"})

	for _, c := range result.Checks {
		if c.ID == "prompt_md" {
			if c.Status != StatusPass {
				t.Fatalf("prompt_md status = %q, want %q", c.Status, StatusPass)
			}
			return
		}
	}
	t.Fatal("prompt_md check not found")
}

func TestRun_Deterministic(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	setupHalDir(t, dir)
	installSkills(t, dir)
	installCommands(t, dir)

	opts := Options{Dir: dir, Engine: "pi"}

	result1 := Run(opts)
	result2 := Run(opts)

	if result1.OverallStatus != result2.OverallStatus {
		t.Fatalf("overallStatus not deterministic: %q vs %q", result1.OverallStatus, result2.OverallStatus)
	}
	if len(result1.Checks) != len(result2.Checks) {
		t.Fatalf("check count not deterministic: %d vs %d", len(result1.Checks), len(result2.Checks))
	}
	for i := range result1.Checks {
		if result1.Checks[i].ID != result2.Checks[i].ID {
			t.Fatalf("check[%d].ID not deterministic: %q vs %q", i, result1.Checks[i].ID, result2.Checks[i].ID)
		}
		if result1.Checks[i].Status != result2.Checks[i].Status {
			t.Fatalf("check[%d].Status not deterministic: %q vs %q", i, result1.Checks[i].ID, result2.Checks[i].Status)
		}
	}
	if result1.TotalChecks != result2.TotalChecks {
		t.Fatalf("totalChecks not deterministic: %d vs %d", result1.TotalChecks, result2.TotalChecks)
	}
	if result1.PassedChecks != result2.PassedChecks {
		t.Fatalf("passedChecks not deterministic: %d vs %d", result1.PassedChecks, result2.PassedChecks)
	}
}

func TestRun_ScopeAndApplicability(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	setupHalDir(t, dir)
	installSkills(t, dir)
	installCommands(t, dir)

	result := Run(Options{Dir: dir, Engine: "pi"})

	for _, c := range result.Checks {
		if c.Scope == "" {
			t.Errorf("check %q missing scope", c.ID)
		}
		if c.Applicability == "" {
			t.Errorf("check %q missing applicability", c.ID)
		}
	}

	// GitHub auth check should be not_applicable when there is no valid GitHub origin remote
	for _, c := range result.Checks {
		if c.ID == "github_auth" {
			if c.Applicability != ApplicabilityNotApplicable {
				t.Fatalf("github_auth applicability = %q, want %q", c.Applicability, ApplicabilityNotApplicable)
			}
			if c.Scope != ScopeRepo {
				t.Fatalf("github_auth scope = %q, want %q", c.Scope, ScopeRepo)
			}
		}
	}

	// Codex check should be not_applicable for pi engine
	for _, c := range result.Checks {
		if c.ID == "codex_global_links" {
			if c.Applicability != ApplicabilityNotApplicable {
				t.Fatalf("codex_global_links applicability = %q, want %q for pi engine",
					c.Applicability, ApplicabilityNotApplicable)
			}
			if c.Scope != ScopeEngineGlobal {
				t.Fatalf("codex_global_links scope = %q, want %q", c.Scope, ScopeEngineGlobal)
			}
		}
	}

	// Legacy debris should be migration scope
	for _, c := range result.Checks {
		if c.ID == "legacy_debris" {
			if c.Scope != ScopeMigration {
				t.Fatalf("legacy_debris scope = %q, want %q", c.Scope, ScopeMigration)
			}
		}
	}
}

func TestRun_InvalidPRDJSON(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	halDir := setupHalDir(t, dir)
	installSkills(t, dir)
	installCommands(t, dir)
	// Write invalid JSON
	os.WriteFile(filepath.Join(halDir, template.PRDFile), []byte("{invalid json"), 0644)

	result := Run(Options{Dir: dir, Engine: "pi"})

	for _, c := range result.Checks {
		if c.ID == "prd_json" {
			if c.Status != StatusWarn {
				t.Fatalf("prd_json status = %q, want %q for invalid JSON", c.Status, StatusWarn)
			}
			return
		}
	}
	t.Fatal("prd_json check not found")
}

func TestRun_ValidPRDJSON(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	halDir := setupHalDir(t, dir)
	installSkills(t, dir)
	installCommands(t, dir)
	os.WriteFile(filepath.Join(halDir, template.PRDFile), []byte(`{"stories":[{"id":"US-001","status":"pending"}]}`), 0644)

	result := Run(Options{Dir: dir, Engine: "pi"})

	for _, c := range result.Checks {
		if c.ID == "prd_json" {
			if c.Status != StatusPass {
				t.Fatalf("prd_json status = %q, want %q", c.Status, StatusPass)
			}
			return
		}
	}
	t.Fatal("prd_json check not found")
}

func TestRun_NoPRDJSON(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	setupHalDir(t, dir)
	installSkills(t, dir)
	installCommands(t, dir)
	// No prd.json — should skip

	result := Run(Options{Dir: dir, Engine: "pi"})

	for _, c := range result.Checks {
		if c.ID == "prd_json" {
			if c.Status != StatusSkip {
				t.Fatalf("prd_json status = %q, want %q (no prd.json)", c.Status, StatusSkip)
			}
			return
		}
	}
	t.Fatal("prd_json check not found")
}

func TestRun_CheckCount(t *testing.T) {
	// A fully healthy repo should have exactly 15 checks
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	halDir := setupHalDir(t, dir)
	installSkills(t, dir)
	installCommands(t, dir)
	os.WriteFile(filepath.Join(halDir, template.PRDFile), []byte(`{"stories":[{"id":"US-001","status":"pending"}]}`), 0644)

	result := Run(Options{Dir: dir, Engine: "pi"})

	// Expected checks in order
	expectedIDs := []string{
		"git_repo",
		"hal_dir",
		"config_yaml",
		"github_auth",
		"default_engine_cli",
		"prompt_md",
		"progress_file",
		"prd_json",
		"hal_skills",
		"hal_commands",
		"local_skill_links",
		"codex_global_links",
		"legacy_debris",
		"legacy_sandbox_state",
		"broken_skill_links",
	}

	if result.TotalChecks != len(expectedIDs) {
		t.Fatalf("totalChecks = %d, want %d", result.TotalChecks, len(expectedIDs))
	}

	for i, expected := range expectedIDs {
		if i >= len(result.Checks) {
			t.Fatalf("missing check at index %d: expected %q", i, expected)
		}
		if result.Checks[i].ID != expected {
			t.Fatalf("check[%d].ID = %q, want %q", i, result.Checks[i].ID, expected)
		}
	}
}

func TestCheckGitHubAuth_NonGitDirectoryIsNotApplicable(t *testing.T) {
	check := checkGitHubAuthWithDeps(t.TempDir(), githubAuthDeps{
		originRemoteURL: func(string) (string, error) {
			return "", errNotGitRepository
		},
		selectGitHubClient: func(context.Context) (ci.ClientSelection, error) {
			t.Fatal("selectGitHubClient should not be called when repository is not git")
			return ci.ClientSelection{}, nil
		},
	})

	if check.Status != StatusSkip {
		t.Fatalf("status = %q, want %q", check.Status, StatusSkip)
	}
	if check.Severity != SeverityInfo {
		t.Fatalf("severity = %q, want %q", check.Severity, SeverityInfo)
	}
}

func TestCheckGitHubAuth_MissingOriginIsNotApplicable(t *testing.T) {
	check := checkGitHubAuthWithDeps(t.TempDir(), githubAuthDeps{
		originRemoteURL: func(string) (string, error) {
			return "", ci.ErrMissingOriginRemote
		},
		selectGitHubClient: func(context.Context) (ci.ClientSelection, error) {
			t.Fatal("selectGitHubClient should not be called when origin remote is missing")
			return ci.ClientSelection{}, nil
		},
	})

	if check.Status != StatusSkip {
		t.Fatalf("status = %q, want %q", check.Status, StatusSkip)
	}
	if check.Message != "GitHub auth check is not applicable: origin remote is not configured." {
		t.Fatalf("message = %q", check.Message)
	}
}

func TestCheckGitHubAuth_NonGitHubOriginIsNotApplicable(t *testing.T) {
	check := checkGitHubAuthWithDeps(t.TempDir(), githubAuthDeps{
		originRemoteURL: func(string) (string, error) {
			return "git@gitlab.com:acme/repo.git", nil
		},
		selectGitHubClient: func(context.Context) (ci.ClientSelection, error) {
			t.Fatal("selectGitHubClient should not be called for non-GitHub origins")
			return ci.ClientSelection{}, nil
		},
	})

	if check.Status != StatusSkip {
		t.Fatalf("status = %q, want %q", check.Status, StatusSkip)
	}
	if check.Message != "GitHub auth check is not applicable: origin remote is not hosted on GitHub." {
		t.Fatalf("message = %q", check.Message)
	}
}

func TestCheckGitHubAuth_GitHubOriginWithoutAuthWarns(t *testing.T) {
	check := checkGitHubAuthWithDeps(t.TempDir(), githubAuthDeps{
		originRemoteURL: func(string) (string, error) {
			return "git@github.com:acme/repo.git", nil
		},
		selectGitHubClient: func(context.Context) (ci.ClientSelection, error) {
			return ci.ClientSelection{}, ci.ErrNoGitHubAuth
		},
	})

	if check.Status != StatusWarn {
		t.Fatalf("status = %q, want %q", check.Status, StatusWarn)
	}
	if check.RemediationID != RemediationRunGHAuthLogin {
		t.Fatalf("remediationId = %q, want %q", check.RemediationID, RemediationRunGHAuthLogin)
	}
	if check.Remediation == nil {
		t.Fatal("remediation should not be nil")
	}
	if check.Remediation.Command != "gh auth login" {
		t.Fatalf("remediation.command = %q, want %q", check.Remediation.Command, "gh auth login")
	}
	if check.Remediation.Safe {
		t.Fatal("remediation.safe = true, want false")
	}
}

func TestCheckGitHubAuth_GitHubOriginWithAuthPasses(t *testing.T) {
	check := checkGitHubAuthWithDeps(t.TempDir(), githubAuthDeps{
		originRemoteURL: func(string) (string, error) {
			return "https://github.com/acme/repo.git", nil
		},
		selectGitHubClient: func(context.Context) (ci.ClientSelection, error) {
			return ci.ClientSelection{Kind: ci.ClientKindGH}, nil
		},
	})

	if check.Status != StatusPass {
		t.Fatalf("status = %q, want %q", check.Status, StatusPass)
	}
	if check.Remediation != nil {
		t.Fatalf("remediation = %+v, want nil", check.Remediation)
	}
}

func TestGitOriginRemoteURL_NotGitRepository(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello"), 0644); err != nil {
		t.Fatalf("write README: %v", err)
	}

	remote, err := gitOriginRemoteURL(dir)
	if remote != "" {
		t.Fatalf("remote = %q, want empty", remote)
	}
	if !errors.Is(err, errNotGitRepository) {
		t.Fatalf("error = %v, want errNotGitRepository", err)
	}
}

func TestGitOriginRemoteURL_GitRepoMissingOrigin(t *testing.T) {
	dir := t.TempDir()

	cmd := exec.Command("git", "-C", dir, "init")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}

	remote, err := gitOriginRemoteURL(dir)
	if remote != "" {
		t.Fatalf("remote = %q, want empty", remote)
	}
	if !errors.Is(err, ci.ErrMissingOriginRemote) {
		t.Fatalf("error = %v, want ci.ErrMissingOriginRemote", err)
	}
}

func TestRun_PRDWithNoStoriesKey(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	halDir := setupHalDir(t, dir)
	installSkills(t, dir)
	installCommands(t, dir)
	// Valid JSON but no stories key
	os.WriteFile(filepath.Join(halDir, template.PRDFile), []byte(`{"project":"test","description":"desc"}`), 0644)

	result := Run(Options{Dir: dir, Engine: "pi"})

	for _, c := range result.Checks {
		if c.ID == "prd_json" {
			if c.Status != StatusWarn {
				t.Fatalf("prd_json status = %q, want %q (missing stories key)", c.Status, StatusWarn)
			}
			return
		}
	}
	t.Fatal("prd_json check not found")
}

func TestRun_EarlyReturn_HasCorrectEngine(t *testing.T) {
	// When .hal/ is missing, the early return should still report the engine
	dir := t.TempDir()
	result := Run(Options{Dir: dir, Engine: "claude"})

	if result.Engine != "claude" {
		t.Fatalf("engine = %q, want %q", result.Engine, "claude")
	}
}

func TestRun_LegacySandboxStateDetected(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	halDir := setupHalDir(t, dir)
	installSkills(t, dir)
	installCommands(t, dir)

	// Create legacy sandbox.json
	os.WriteFile(filepath.Join(halDir, template.SandboxFile), []byte(`{"name":"test"}`), 0644)

	result := Run(Options{Dir: dir, Engine: "pi"})

	found := false
	for _, c := range result.Checks {
		if c.ID == "legacy_sandbox_state" {
			found = true
			if c.Status != StatusWarn {
				t.Fatalf("legacy_sandbox_state status = %q, want %q", c.Status, StatusWarn)
			}
			if c.Severity != SeverityWarn {
				t.Fatalf("legacy_sandbox_state severity = %q, want %q", c.Severity, SeverityWarn)
			}
			if c.Scope != ScopeMigration {
				t.Fatalf("legacy_sandbox_state scope = %q, want %q", c.Scope, ScopeMigration)
			}
			if c.Applicability != ApplicabilityOptional {
				t.Fatalf("legacy_sandbox_state applicability = %q, want %q", c.Applicability, ApplicabilityOptional)
			}
			if c.Remediation == nil {
				t.Fatal("legacy_sandbox_state should have remediation")
			}
			if c.Remediation.Command != "hal sandbox migrate" {
				t.Fatalf("remediation.command = %q, want %q", c.Remediation.Command, "hal sandbox migrate")
			}
			if !c.Remediation.Safe {
				t.Fatal("remediation.safe should be true")
			}
			expectedMsg := "Legacy .hal/sandbox.json found — run 'hal sandbox migrate'"
			if c.Message != expectedMsg {
				t.Fatalf("message = %q, want %q", c.Message, expectedMsg)
			}
		}
	}
	if !found {
		t.Fatal("legacy_sandbox_state check not found")
	}

	// Should appear in warnings
	foundWarning := false
	for _, w := range result.Warnings {
		if w == "legacy_sandbox_state" {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Fatalf("warnings = %v, want legacy_sandbox_state in list", result.Warnings)
	}
}

func TestRun_NoLegacySandboxState(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	setupHalDir(t, dir)
	installSkills(t, dir)
	installCommands(t, dir)

	result := Run(Options{Dir: dir, Engine: "pi"})

	for _, c := range result.Checks {
		if c.ID == "legacy_sandbox_state" {
			if c.Status != StatusPass {
				t.Fatalf("legacy_sandbox_state status = %q, want %q (no sandbox.json present)", c.Status, StatusPass)
			}
			return
		}
	}
	t.Fatal("legacy_sandbox_state check not found")
}

func TestRun_LegacySandboxStateRemediation(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	halDir := setupHalDir(t, dir)
	installSkills(t, dir)
	installCommands(t, dir)
	// Add legacy sandbox state
	os.WriteFile(filepath.Join(halDir, template.SandboxFile), []byte(`{"name":"test"}`), 0644)

	result := Run(Options{Dir: dir, Engine: "pi"})

	// Primary remediation should be hal sandbox migrate (it's the first warning with a command)
	if result.PrimaryRemediation == nil {
		t.Fatal("primaryRemediation should not be nil")
	}
	if result.PrimaryRemediation.Command != "hal sandbox migrate" {
		t.Fatalf("primaryRemediation.command = %q, want %q", result.PrimaryRemediation.Command, "hal sandbox migrate")
	}
	if !result.PrimaryRemediation.Safe {
		t.Fatal("primaryRemediation.safe should be true")
	}
}

func TestRun_LegacySandboxStateWarSummary(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	halDir := setupHalDir(t, dir)
	installSkills(t, dir)
	installCommands(t, dir)
	os.WriteFile(filepath.Join(halDir, template.SandboxFile), []byte(`{"name":"test"}`), 0644)

	result := Run(Options{Dir: dir, Engine: "pi"})

	if result.OverallStatus != StatusWarn {
		t.Fatalf("overallStatus = %q, want %q", result.OverallStatus, StatusWarn)
	}
	if result.Summary == "" {
		t.Fatal("summary should not be empty")
	}
	if !strings.Contains(result.Summary, "hal sandbox migrate") {
		t.Fatalf("summary = %q, should contain 'hal sandbox migrate'", result.Summary)
	}
}

func TestRun_GracefulWithMinimalSetup(t *testing.T) {
	// Just .hal/ dir, nothing else — should not panic or error
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)

	result := Run(Options{Dir: dir, Engine: "pi"})

	// Should complete without panic
	if result.ContractVersion != ContractVersion {
		t.Fatalf("contractVersion = %d, want %d", result.ContractVersion, ContractVersion)
	}
	// Should have some failing checks (no config, no skills, etc.)
	if result.OverallStatus == StatusPass {
		t.Fatal("should not pass with minimal setup")
	}
	if result.TotalChecks == 0 {
		t.Fatal("should have some checks")
	}
}
