// Package doctor implements health/readiness checks for hal.
//
// The Check function inspects the project environment and returns
// a structured DoctorResult describing whether hal is ready to use.
package doctor

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/skills"
	"github.com/jywlabs/hal/internal/template"
)

// ContractVersion is the current version of the doctor contract.
const ContractVersion = 1

// Check status values.
const (
	StatusPass = "pass"
	StatusFail = "fail"
	StatusWarn = "warn"
	StatusSkip = "skip"
)

// Check severity values.
const (
	SeverityInfo  = "info"
	SeverityWarn  = "warn"
	SeverityError = "error"
)

// Remediation IDs.
const (
	RemediationNone             = "none"
	RemediationRunHalInit       = "run_hal_init"
	RemediationRefreshCodexLinks = "refresh_codex_links"
)

// DoctorResult is the v1 machine-readable doctor contract.
type DoctorResult struct {
	ContractVersion int      `json:"contractVersion"`
	OverallStatus   string   `json:"overallStatus"`
	Checks          []Check  `json:"checks"`
	Failures        []string `json:"failures"`
	Warnings        []string `json:"warnings"`
	Summary         string   `json:"summary"`
}

// Check is a single health check result.
type Check struct {
	ID            string `json:"id"`
	Status        string `json:"status"`
	Severity      string `json:"severity"`
	RemediationID string `json:"remediationId"`
	Message       string `json:"message"`
}

// Options configures the doctor run.
type Options struct {
	// Dir is the project root directory.
	Dir string
	// Engine is the configured default engine name (e.g., "codex", "claude", "pi").
	// When non-empty, engine-specific checks are scoped appropriately.
	Engine string
}

// Run inspects the environment and returns a DoctorResult.
func Run(opts Options) DoctorResult {
	dir := opts.Dir
	if dir == "" {
		dir = "."
	}

	var checks []Check
	var failures []string
	var warnings []string

	// 1. Git repo
	checks = append(checks, checkGitRepo(dir))

	// 2. .hal/ directory
	halDir := filepath.Join(dir, template.HalDir)
	halCheck := checkHalDir(halDir)
	checks = append(checks, halCheck)

	if halCheck.Status != StatusPass {
		// Can't check further without .hal/
		checks = append(checks, Check{
			ID:            "config_yaml",
			Status:        StatusSkip,
			Severity:      SeverityInfo,
			RemediationID: RemediationNone,
			Message:       "Skipped: .hal/ directory not found.",
		})

		failures = append(failures, "hal_dir")
		return DoctorResult{
			ContractVersion: ContractVersion,
			OverallStatus:   StatusFail,
			Checks:          checks,
			Failures:        failures,
			Warnings:        warnings,
			Summary:         "Hal is not initialized. Run hal init.",
		}
	}

	// 3. config.yaml
	checks = append(checks, checkConfigYAML(halDir))

	// 4. Default engine CLI
	engine := opts.Engine
	if engine == "" {
		engine = "codex"
	}
	checks = append(checks, checkEngineCLI(engine))

	// 5. Hal skills
	skillCheck := checkSkills(dir)
	checks = append(checks, skillCheck)
	if skillCheck.Status == StatusFail {
		failures = append(failures, "hal_skills")
	}

	// 6. Hal commands
	cmdCheck := checkCommands(dir)
	checks = append(checks, cmdCheck)
	if cmdCheck.Status == StatusFail {
		failures = append(failures, "hal_commands")
	}

	// 7. Codex global links (only applicable for codex engine)
	codexCheck := checkCodexLinks(dir, engine)
	checks = append(checks, codexCheck)
	if codexCheck.Status == StatusWarn {
		warnings = append(warnings, "codex_global_links")
	}

	// Determine overall status
	overall := StatusPass
	if len(failures) > 0 {
		overall = StatusFail
	} else if len(warnings) > 0 {
		overall = StatusWarn
	}

	summary := "Hal is ready to use."
	if overall == StatusFail {
		summary = "Hal is not ready yet: run hal init."
	} else if overall == StatusWarn {
		summary = "Hal is usable with warnings."
	}

	return DoctorResult{
		ContractVersion: ContractVersion,
		OverallStatus:   overall,
		Checks:          checks,
		Failures:        failures,
		Warnings:        warnings,
		Summary:         summary,
	}
}

func checkGitRepo(dir string) Check {
	gitDir := filepath.Join(dir, ".git")
	if info, err := os.Stat(gitDir); err == nil && info.IsDir() {
		return Check{
			ID:            "git_repo",
			Status:        StatusPass,
			Severity:      SeverityInfo,
			RemediationID: RemediationNone,
			Message:       "Git repository detected.",
		}
	}
	return Check{
		ID:            "git_repo",
		Status:        StatusWarn,
		Severity:      SeverityWarn,
		RemediationID: RemediationNone,
		Message:       "No .git directory found. Hal works best inside a git repository.",
	}
}

func checkHalDir(halDir string) Check {
	if info, err := os.Stat(halDir); err == nil && info.IsDir() {
		return Check{
			ID:            "hal_dir",
			Status:        StatusPass,
			Severity:      SeverityInfo,
			RemediationID: RemediationNone,
			Message:       "Found .hal/ directory.",
		}
	}
	return Check{
		ID:            "hal_dir",
		Status:        StatusFail,
		Severity:      SeverityError,
		RemediationID: RemediationRunHalInit,
		Message:       "Missing .hal/ directory.",
	}
}

func checkConfigYAML(halDir string) Check {
	configPath := filepath.Join(halDir, template.ConfigFile)
	if _, err := os.Stat(configPath); err == nil {
		return Check{
			ID:            "config_yaml",
			Status:        StatusPass,
			Severity:      SeverityInfo,
			RemediationID: RemediationNone,
			Message:       "Loaded .hal/config.yaml.",
		}
	}
	return Check{
		ID:            "config_yaml",
		Status:        StatusWarn,
		Severity:      SeverityWarn,
		RemediationID: RemediationRunHalInit,
		Message:       "Missing .hal/config.yaml. Using defaults.",
	}
}

func checkEngineCLI(engine string) Check {
	cliName := engineCLIName(engine)
	if _, err := exec.LookPath(cliName); err == nil {
		return Check{
			ID:            "default_engine_cli",
			Status:        StatusPass,
			Severity:      SeverityInfo,
			RemediationID: RemediationNone,
			Message:       "The configured default engine CLI is available in PATH.",
		}
	}
	return Check{
		ID:            "default_engine_cli",
		Status:        StatusWarn,
		Severity:      SeverityWarn,
		RemediationID: RemediationNone,
		Message:       "The configured default engine CLI (" + cliName + ") was not found in PATH.",
	}
}

func checkSkills(dir string) Check {
	skillsDir := filepath.Join(dir, template.HalDir, "skills")
	var missing []string

	for _, name := range skills.ManagedSkillNames {
		skillPath := filepath.Join(skillsDir, name)
		if _, err := os.Stat(skillPath); os.IsNotExist(err) {
			missing = append(missing, name)
		}
	}

	if len(missing) == 0 {
		return Check{
			ID:            "hal_skills",
			Status:        StatusPass,
			Severity:      SeverityInfo,
			RemediationID: RemediationNone,
			Message:       "Installed Hal skills are present.",
		}
	}

	return Check{
		ID:            "hal_skills",
		Status:        StatusFail,
		Severity:      SeverityError,
		RemediationID: RemediationRunHalInit,
		Message:       "Missing installed Hal skills: " + strings.Join(missing, ", ") + ".",
	}
}

func checkCommands(dir string) Check {
	commandsDir := filepath.Join(dir, template.HalDir, template.CommandsDir)
	var missing []string

	for _, name := range skills.CommandNames {
		cmdPath := filepath.Join(commandsDir, name+".md")
		if _, err := os.Stat(cmdPath); os.IsNotExist(err) {
			missing = append(missing, name)
		}
	}

	if len(missing) == 0 {
		return Check{
			ID:            "hal_commands",
			Status:        StatusPass,
			Severity:      SeverityInfo,
			RemediationID: RemediationNone,
			Message:       "Installed Hal commands are present.",
		}
	}

	return Check{
		ID:            "hal_commands",
		Status:        StatusFail,
		Severity:      SeverityError,
		RemediationID: RemediationRunHalInit,
		Message:       "Missing installed Hal commands: " + strings.Join(missing, ", ") + ".",
	}
}

func checkCodexLinks(dir, engine string) Check {
	// Skip Codex link check if engine is not codex
	if engine != "codex" {
		return Check{
			ID:            "codex_global_links",
			Status:        StatusSkip,
			Severity:      SeverityInfo,
			RemediationID: RemediationNone,
			Message:       "Codex global links are not required because the configured engine is " + engine + ".",
		}
	}

	linker := skills.GetLinker("codex")
	if linker == nil {
		return Check{
			ID:            "codex_global_links",
			Status:        StatusSkip,
			Severity:      SeverityInfo,
			RemediationID: RemediationNone,
			Message:       "Codex linker not available.",
		}
	}

	// Check if skills directory exists and has correct links
	skillsDir := linker.SkillsDir()
	absDir, _ := filepath.Abs(dir)

	var broken []string
	for _, name := range skills.ManagedSkillNames {
		link := filepath.Join(skillsDir, name)
		target, err := os.Readlink(link)
		if err != nil {
			broken = append(broken, name)
			continue
		}
		expectedTarget := filepath.Join(absDir, template.HalDir, "skills", name)
		if target != expectedTarget {
			broken = append(broken, name)
		}
	}

	if len(broken) == 0 {
		return Check{
			ID:            "codex_global_links",
			Status:        StatusPass,
			Severity:      SeverityInfo,
			RemediationID: RemediationNone,
			Message:       "Codex global links point to this repo.",
		}
	}

	return Check{
		ID:            "codex_global_links",
		Status:        StatusWarn,
		Severity:      SeverityWarn,
		RemediationID: RemediationRefreshCodexLinks,
		Message:       "Codex global links are missing or stale and need refresh.",
	}
}

func engineCLIName(engine string) string {
	switch strings.ToLower(engine) {
	case "claude":
		return "claude"
	case "pi":
		return "pi"
	default:
		return "codex"
	}
}
