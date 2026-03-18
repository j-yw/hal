package doctor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

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
