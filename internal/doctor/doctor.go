// Package doctor implements health/readiness checks for hal.
//
// The Check function inspects the project environment and returns
// a structured DoctorResult describing whether hal is ready to use.
package doctor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/ci"
	"github.com/jywlabs/hal/internal/skills"
	"github.com/jywlabs/hal/internal/template"
	"gopkg.in/yaml.v3"
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
	RemediationNone              = "none"
	RemediationRunHalInit        = "run_hal_init"
	RemediationRefreshCodexLinks = "refresh_codex_links"
	RemediationRunGHAuthLogin    = "run_gh_auth_login"
)

// DoctorResult is the v1 machine-readable doctor contract.
type DoctorResult struct {
	ContractVersion    int          `json:"contractVersion"`
	OverallStatus      string       `json:"overallStatus"`
	Engine             string       `json:"engine"`
	Checks             []Check      `json:"checks"`
	TotalChecks        int          `json:"totalChecks"`
	PassedChecks       int          `json:"passedChecks"`
	Failures           []string     `json:"failures"`
	Warnings           []string     `json:"warnings"`
	PrimaryRemediation *Remediation `json:"primaryRemediation,omitempty"`
	Summary            string       `json:"summary"`
}

// Applicability values for checks.
const (
	ApplicabilityRequired      = "required"
	ApplicabilityOptional      = "optional"
	ApplicabilityNotApplicable = "not_applicable"
)

// Scope values for checks.
const (
	ScopeRepo         = "repo"
	ScopeEngineLocal  = "engine_local"
	ScopeEngineGlobal = "engine_global"
	ScopeMigration    = "migration"
)

// Check is a single health check result.
type Check struct {
	ID            string `json:"id"`
	Status        string `json:"status"`
	Severity      string `json:"severity"`
	Scope         string `json:"scope,omitempty"`
	Applicability string `json:"applicability,omitempty"`
	RemediationID string `json:"remediationId"`
	Message       string `json:"message"`
	// Remediation provides an actionable command to fix the issue.
	Remediation *Remediation `json:"remediation,omitempty"`
}

// Remediation describes how to fix a failed or warned check.
type Remediation struct {
	Command string `json:"command"`
	Safe    bool   `json:"safe"` // Whether auto-applying is safe
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

	engine := opts.Engine
	if engine == "" {
		engine = "codex"
	}

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
			Scope:         ScopeRepo,
			Applicability: ApplicabilityRequired,
			RemediationID: RemediationNone,
			Message:       "Skipped: .hal/ directory not found.",
		})

		failures = append(failures, "hal_dir")
		passed := countPassed(checks)
		return DoctorResult{
			ContractVersion:    ContractVersion,
			OverallStatus:      StatusFail,
			Engine:             engine,
			Checks:             checks,
			TotalChecks:        len(checks),
			PassedChecks:       passed,
			Failures:           failures,
			Warnings:           warnings,
			PrimaryRemediation: halCheck.Remediation,
			Summary:            "Hal is not initialized. Run hal init.",
		}
	}

	// 3. config.yaml
	checks = append(checks, checkConfigYAML(halDir))

	// 4. GitHub auth readiness (only applicable for GitHub remotes)
	githubAuthCheck := checkGitHubAuth(dir)
	checks = append(checks, githubAuthCheck)
	if githubAuthCheck.Status == StatusWarn {
		warnings = append(warnings, "github_auth")
	}

	// 5. Default engine CLI
	checks = append(checks, checkEngineCLI(engine))

	// 6. Prompt template
	promptCheck := checkPromptMD(halDir)
	checks = append(checks, promptCheck)
	if promptCheck.Status == StatusWarn {
		warnings = append(warnings, "prompt_md")
	}

	// 7. Progress file
	progressCheck := checkProgressFile(halDir)
	checks = append(checks, progressCheck)

	// 8. PRD validity (only when prd.json exists)
	prdCheck := checkPRDJSON(halDir)
	checks = append(checks, prdCheck)
	if prdCheck.Status == StatusWarn {
		warnings = append(warnings, "prd_json")
	}

	// 9. Hal skills
	skillCheck := checkSkills(dir)
	checks = append(checks, skillCheck)
	if skillCheck.Status == StatusFail {
		failures = append(failures, "hal_skills")
	}

	// 10. Hal commands
	cmdCheck := checkCommands(dir)
	checks = append(checks, cmdCheck)
	if cmdCheck.Status == StatusFail {
		failures = append(failures, "hal_commands")
	}

	// 11. Engine-local skill links (.claude/skills, .pi/skills)
	localLinksCheck := checkLocalSkillLinks(dir)
	checks = append(checks, localLinksCheck)
	if localLinksCheck.Status == StatusWarn {
		warnings = append(warnings, "local_skill_links")
	}

	// 12. Codex global links (only applicable for codex engine)
	codexCheck := checkCodexLinks(dir, engine)
	checks = append(checks, codexCheck)
	if codexCheck.Status == StatusWarn {
		warnings = append(warnings, "codex_global_links")
	}

	// 13. Legacy migration debris
	legacyCheck := checkLegacyDebris(dir)
	checks = append(checks, legacyCheck)
	if legacyCheck.Status == StatusWarn {
		warnings = append(warnings, "legacy_debris")
	}

	// 14. Legacy sandbox state (.hal/sandbox.json)
	legacySandboxCheck := checkLegacySandboxState(halDir)
	checks = append(checks, legacySandboxCheck)
	if legacySandboxCheck.Status == StatusWarn {
		warnings = append(warnings, "legacy_sandbox_state")
	}

	// 15. Broken symlinks in engine skill directories
	brokenCheck := checkBrokenSkillLinks(dir)
	checks = append(checks, brokenCheck)
	if brokenCheck.Status == StatusWarn {
		warnings = append(warnings, "broken_skill_links")
	}

	// Determine overall status
	overall := StatusPass
	if len(failures) > 0 {
		overall = StatusFail
	} else if len(warnings) > 0 {
		overall = StatusWarn
	}

	// Set scope and applicability for all checks
	for i := range checks {
		c := &checks[i]
		switch c.ID {
		case "git_repo", "hal_dir", "config_yaml", "prompt_md", "progress_file", "hal_skills", "hal_commands":
			c.Scope = ScopeRepo
			c.Applicability = ApplicabilityRequired
		case "github_auth":
			c.Scope = ScopeRepo
			if c.Status == StatusSkip {
				c.Applicability = ApplicabilityNotApplicable
			} else {
				c.Applicability = ApplicabilityOptional
			}
		case "default_engine_cli":
			c.Scope = ScopeRepo
			c.Applicability = ApplicabilityRequired
		case "prd_json":
			c.Scope = ScopeRepo
			c.Applicability = ApplicabilityOptional
		case "local_skill_links":
			c.Scope = ScopeEngineLocal
			c.Applicability = ApplicabilityOptional
		case "codex_global_links":
			c.Scope = ScopeEngineGlobal
			if engine == "codex" {
				c.Applicability = ApplicabilityOptional
			} else {
				c.Applicability = ApplicabilityNotApplicable
			}
		case "legacy_debris", "legacy_sandbox_state", "broken_skill_links":
			c.Scope = ScopeMigration
			c.Applicability = ApplicabilityOptional
		}
	}

	// Find primary remediation from first failing/warning check with a command
	var primaryRemediation *Remediation
	for _, c := range checks {
		if (c.Status == StatusFail || c.Status == StatusWarn) && c.Remediation != nil {
			primaryRemediation = c.Remediation
			break
		}
	}

	summary := "Hal is ready to use."
	if overall == StatusFail {
		if len(failures) == 1 && failures[0] == "hal_dir" {
			summary = "Hal is not initialized. Run hal init."
		} else {
			summary = "Hal is not ready yet: run hal init."
		}
	} else if overall == StatusWarn {
		// Build specific warning summary
		warnParts := make([]string, 0, len(warnings))
		for _, w := range warnings {
			switch w {
			case "codex_global_links":
				warnParts = append(warnParts, "refresh Codex global links")
			case "github_auth":
				warnParts = append(warnParts, "run gh auth login")
			case "legacy_debris":
				warnParts = append(warnParts, "run hal cleanup")
			case "legacy_sandbox_state":
				warnParts = append(warnParts, "run hal sandbox migrate")
			case "broken_skill_links":
				warnParts = append(warnParts, "run hal links clean")
			case "local_skill_links":
				warnParts = append(warnParts, "run hal links refresh")
			default:
				warnParts = append(warnParts, w)
			}
		}
		if len(warnParts) > 0 {
			summary = "Hal is usable with warnings: " + strings.Join(warnParts, "; ") + "."
		} else {
			summary = "Hal is usable with warnings."
		}
	}

	passed := countPassed(checks)
	return DoctorResult{
		ContractVersion:    ContractVersion,
		OverallStatus:      overall,
		Engine:             engine,
		Checks:             checks,
		TotalChecks:        len(checks),
		PassedChecks:       passed,
		Failures:           failures,
		Warnings:           warnings,
		PrimaryRemediation: primaryRemediation,
		Summary:            summary,
	}
}

func countPassed(checks []Check) int {
	n := 0
	for _, c := range checks {
		if c.Status == StatusPass {
			n++
		}
	}
	return n
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
		Remediation:   &Remediation{Command: "hal init", Safe: true},
	}
}

func checkConfigYAML(halDir string) Check {
	configPath := filepath.Join(halDir, template.ConfigFile)
	data, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		return Check{
			ID:            "config_yaml",
			Status:        StatusWarn,
			Severity:      SeverityWarn,
			RemediationID: RemediationRunHalInit,
			Message:       "Missing .hal/config.yaml. Using defaults.",
			Remediation:   &Remediation{Command: "hal init", Safe: true},
		}
	}
	if err != nil {
		return Check{
			ID:            "config_yaml",
			Status:        StatusFail,
			Severity:      SeverityError,
			RemediationID: RemediationRunHalInit,
			Message:       "Cannot read .hal/config.yaml: " + err.Error(),
			Remediation:   &Remediation{Command: "hal init --refresh-templates", Safe: false},
		}
	}

	// Validate YAML is parseable
	var raw map[string]interface{}
	if yamlErr := yaml.Unmarshal(data, &raw); yamlErr != nil {
		return Check{
			ID:            "config_yaml",
			Status:        StatusFail,
			Severity:      SeverityError,
			RemediationID: RemediationRunHalInit,
			Message:       "Invalid YAML in .hal/config.yaml: " + yamlErr.Error(),
			Remediation:   &Remediation{Command: "hal init --refresh-templates", Safe: false},
		}
	}

	return Check{
		ID:            "config_yaml",
		Status:        StatusPass,
		Severity:      SeverityInfo,
		RemediationID: RemediationNone,
		Message:       "Loaded .hal/config.yaml.",
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

var errNotGitRepository = errors.New("not a git repository")

type githubAuthDeps struct {
	originRemoteURL    func(string) (string, error)
	selectGitHubClient func(context.Context) (ci.ClientSelection, error)
}

func checkGitHubAuth(dir string) Check {
	return checkGitHubAuthWithDeps(dir, githubAuthDeps{
		originRemoteURL:    gitOriginRemoteURL,
		selectGitHubClient: ci.SelectGitHubClient,
	})
}

func checkGitHubAuthWithDeps(dir string, deps githubAuthDeps) Check {
	if deps.originRemoteURL == nil {
		deps.originRemoteURL = gitOriginRemoteURL
	}
	if deps.selectGitHubClient == nil {
		deps.selectGitHubClient = ci.SelectGitHubClient
	}

	remoteURL, err := deps.originRemoteURL(dir)
	if err != nil {
		switch {
		case errors.Is(err, errNotGitRepository):
			return Check{
				ID:            "github_auth",
				Status:        StatusSkip,
				Severity:      SeverityInfo,
				RemediationID: RemediationNone,
				Message:       "GitHub auth check is not applicable outside a git repository.",
			}
		case errors.Is(err, ci.ErrMissingOriginRemote):
			return Check{
				ID:            "github_auth",
				Status:        StatusSkip,
				Severity:      SeverityInfo,
				RemediationID: RemediationNone,
				Message:       "GitHub auth check is not applicable: origin remote is not configured.",
			}
		default:
			return Check{
				ID:            "github_auth",
				Status:        StatusWarn,
				Severity:      SeverityWarn,
				RemediationID: RemediationNone,
				Message:       "Unable to determine GitHub auth applicability: " + err.Error(),
			}
		}
	}

	if _, err := ci.ParseGitHubRepository(remoteURL); err != nil {
		switch {
		case errors.Is(err, ci.ErrNonGitHubOriginRemote):
			return Check{
				ID:            "github_auth",
				Status:        StatusSkip,
				Severity:      SeverityInfo,
				RemediationID: RemediationNone,
				Message:       "GitHub auth check is not applicable: origin remote is not hosted on GitHub.",
			}
		case errors.Is(err, ci.ErrInvalidGitHubOriginRemote), errors.Is(err, ci.ErrMissingOriginRemote):
			return Check{
				ID:            "github_auth",
				Status:        StatusSkip,
				Severity:      SeverityInfo,
				RemediationID: RemediationNone,
				Message:       "GitHub auth check is not applicable: origin remote is not a valid GitHub repository.",
			}
		default:
			return Check{
				ID:            "github_auth",
				Status:        StatusWarn,
				Severity:      SeverityWarn,
				RemediationID: RemediationNone,
				Message:       "Unable to parse origin remote for GitHub auth check: " + err.Error(),
			}
		}
	}

	if _, err := deps.selectGitHubClient(context.Background()); err != nil {
		if errors.Is(err, ci.ErrNoGitHubAuth) || errors.Is(err, ci.ErrInvalidEnvToken) {
			return Check{
				ID:            "github_auth",
				Status:        StatusWarn,
				Severity:      SeverityWarn,
				RemediationID: RemediationRunGHAuthLogin,
				Message:       "GitHub auth not configured for this GitHub remote.",
				Remediation:   &Remediation{Command: "gh auth login", Safe: false},
			}
		}
		return Check{
			ID:            "github_auth",
			Status:        StatusWarn,
			Severity:      SeverityWarn,
			RemediationID: RemediationNone,
			Message:       "Unable to verify GitHub auth state: " + err.Error(),
		}
	}

	return Check{
		ID:            "github_auth",
		Status:        StatusPass,
		Severity:      SeverityInfo,
		RemediationID: RemediationNone,
		Message:       "GitHub auth is available for GitHub remote operations.",
	}
}

func gitOriginRemoteURL(dir string) (string, error) {
	cmd := exec.Command("git", "-C", dir, "remote", "get-url", "origin")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errText := strings.ToLower(strings.TrimSpace(stderr.String()))
		switch {
		case strings.Contains(errText, "not a git repository"):
			return "", errNotGitRepository
		case strings.Contains(errText, "no such remote") && strings.Contains(errText, "origin"):
			return "", ci.ErrMissingOriginRemote
		default:
			return "", fmt.Errorf("failed to read git origin remote: %w", err)
		}
	}

	remoteURL := strings.TrimSpace(stdout.String())
	if remoteURL == "" {
		return "", ci.ErrMissingOriginRemote
	}
	return remoteURL, nil
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
		Remediation:   &Remediation{Command: "hal init", Safe: true},
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
		Remediation:   &Remediation{Command: "hal init", Safe: true},
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

	var missing, otherRepo []string
	var otherTarget string
	for _, name := range skills.ManagedSkillNames {
		link := filepath.Join(skillsDir, name)
		target, err := os.Readlink(link)
		if err != nil {
			missing = append(missing, name)
			continue
		}
		expectedTarget := filepath.Join(absDir, template.HalDir, "skills", name)
		if target != expectedTarget {
			otherRepo = append(otherRepo, name)
			if otherTarget == "" {
				otherTarget = target
			}
		}
	}

	if len(missing) == 0 && len(otherRepo) == 0 {
		return Check{
			ID:            "codex_global_links",
			Status:        StatusPass,
			Severity:      SeverityInfo,
			RemediationID: RemediationNone,
			Message:       "Codex global links point to this repo.",
		}
	}

	msg := "Codex global links need refresh."
	if len(otherRepo) > 0 && len(missing) == 0 {
		// All links point to another project
		msg = "Codex global links point to a different project (" + otherTarget + "). Run hal links refresh codex to claim."
	} else if len(missing) > 0 {
		msg = "Codex global links are missing or stale. Run hal links refresh codex."
	}

	return Check{
		ID:            "codex_global_links",
		Status:        StatusWarn,
		Severity:      SeverityWarn,
		RemediationID: RemediationRefreshCodexLinks,
		Message:       msg,
		Remediation:   &Remediation{Command: "hal links refresh codex", Safe: true},
	}
}

func checkLegacyDebris(dir string) Check {
	var debris []string

	// Check for .goralph/ directory
	if _, err := os.Stat(filepath.Join(dir, ".goralph")); err == nil {
		debris = append(debris, ".goralph/")
	}

	// Check for deprecated ralph skill links
	claudeSkills := filepath.Join(dir, ".claude", "skills", "ralph")
	if _, err := os.Lstat(claudeSkills); err == nil {
		debris = append(debris, ".claude/skills/ralph")
	}
	piSkills := filepath.Join(dir, ".pi", "skills", "ralph")
	if _, err := os.Lstat(piSkills); err == nil {
		debris = append(debris, ".pi/skills/ralph")
	}

	// Check for legacy rules/ directory (replaced by standards/)
	if _, err := os.Stat(filepath.Join(dir, template.HalDir, "rules")); err == nil {
		debris = append(debris, ".hal/rules/")
	}

	if len(debris) == 0 {
		return Check{
			ID:            "legacy_debris",
			Status:        StatusPass,
			Severity:      SeverityInfo,
			RemediationID: RemediationNone,
			Message:       "No legacy migration debris found.",
		}
	}

	return Check{
		ID:            "legacy_debris",
		Status:        StatusWarn,
		Severity:      SeverityWarn,
		RemediationID: RemediationRunHalInit,
		Message:       "Legacy debris found: " + strings.Join(debris, ", ") + ". Run hal cleanup.",
		Remediation:   &Remediation{Command: "hal cleanup", Safe: true},
	}
}

func checkPRDJSON(halDir string) Check {
	prdPath := filepath.Join(halDir, template.PRDFile)
	data, err := os.ReadFile(prdPath)
	if os.IsNotExist(err) {
		return Check{
			ID:            "prd_json",
			Status:        StatusSkip,
			Severity:      SeverityInfo,
			RemediationID: RemediationNone,
			Message:       "No prd.json found (normal before first plan/convert).",
		}
	}
	if err != nil {
		return Check{
			ID:            "prd_json",
			Status:        StatusWarn,
			Severity:      SeverityWarn,
			RemediationID: RemediationNone,
			Message:       "Cannot read .hal/prd.json: " + err.Error(),
		}
	}

	// Validate it's parseable JSON with expected structure
	var raw map[string]interface{}
	if jsonErr := json.Unmarshal(data, &raw); jsonErr != nil {
		return Check{
			ID:            "prd_json",
			Status:        StatusWarn,
			Severity:      SeverityWarn,
			RemediationID: RemediationNone,
			Message:       "Invalid JSON in .hal/prd.json: " + jsonErr.Error(),
			Remediation:   &Remediation{Command: "hal convert", Safe: false},
		}
	}

	// Check for stories/userStories key
	_, hasStories := raw["stories"]
	_, hasUserStories := raw["userStories"]
	if !hasStories && !hasUserStories {
		return Check{
			ID:            "prd_json",
			Status:        StatusWarn,
			Severity:      SeverityWarn,
			RemediationID: RemediationNone,
			Message:       "prd.json is missing stories or userStories key.",
			Remediation:   &Remediation{Command: "hal convert", Safe: false},
		}
	}

	return Check{
		ID:            "prd_json",
		Status:        StatusPass,
		Severity:      SeverityInfo,
		RemediationID: RemediationNone,
		Message:       "Loaded .hal/prd.json.",
	}
}

func checkProgressFile(halDir string) Check {
	progressPath := filepath.Join(halDir, template.ProgressFile)
	if _, err := os.Stat(progressPath); os.IsNotExist(err) {
		return Check{
			ID:            "progress_file",
			Status:        StatusWarn,
			Severity:      SeverityWarn,
			RemediationID: RemediationRunHalInit,
			Message:       "Missing .hal/progress.txt. Run history will not be tracked.",
			Remediation:   &Remediation{Command: "hal init", Safe: true},
		}
	}
	return Check{
		ID:            "progress_file",
		Status:        StatusPass,
		Severity:      SeverityInfo,
		RemediationID: RemediationNone,
		Message:       "Found .hal/progress.txt.",
	}
}

func checkPromptMD(halDir string) Check {
	promptPath := filepath.Join(halDir, template.PromptFile)
	data, err := os.ReadFile(promptPath)
	if os.IsNotExist(err) {
		return Check{
			ID:            "prompt_md",
			Status:        StatusWarn,
			Severity:      SeverityWarn,
			RemediationID: RemediationRunHalInit,
			Message:       "Missing .hal/prompt.md. Agent instructions will use defaults.",
			Remediation:   &Remediation{Command: "hal init", Safe: true},
		}
	}
	if err != nil {
		return Check{
			ID:            "prompt_md",
			Status:        StatusWarn,
			Severity:      SeverityWarn,
			RemediationID: RemediationNone,
			Message:       "Cannot read .hal/prompt.md: " + err.Error(),
		}
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return Check{
			ID:            "prompt_md",
			Status:        StatusWarn,
			Severity:      SeverityWarn,
			RemediationID: RemediationRunHalInit,
			Message:       "Empty .hal/prompt.md. Agent will lack project-specific instructions.",
			Remediation:   &Remediation{Command: "hal init --refresh-templates", Safe: false},
		}
	}
	return Check{
		ID:            "prompt_md",
		Status:        StatusPass,
		Severity:      SeverityInfo,
		RemediationID: RemediationNone,
		Message:       "Loaded .hal/prompt.md.",
	}
}

func checkLocalSkillLinks(dir string) Check {
	// Check that .claude/skills/ and .pi/skills/ have correct symlinks to .hal/skills/
	type engineDir struct {
		name      string
		skillsDir string
		prefix    string // relative prefix to .hal/skills/
	}
	engineDirs := []engineDir{
		{name: "claude", skillsDir: filepath.Join(dir, ".claude", "skills"), prefix: filepath.Join("..", "..", template.HalDir, "skills")},
		{name: "pi", skillsDir: filepath.Join(dir, ".pi", "skills"), prefix: filepath.Join("..", "..", template.HalDir, "skills")},
	}

	var stale []string
	for _, ed := range engineDirs {
		for _, skill := range skills.ManagedSkillNames {
			linkPath := filepath.Join(ed.skillsDir, skill)
			info, err := os.Lstat(linkPath)
			if os.IsNotExist(err) {
				// Link doesn't exist — may not have been linked yet (acceptable after fresh init)
				continue
			}
			if err != nil {
				continue
			}
			if info.Mode()&os.ModeSymlink == 0 {
				stale = append(stale, filepath.Join("."+ed.name, "skills", skill))
				continue
			}
			target, err := os.Readlink(linkPath)
			if err != nil {
				continue
			}
			expected := filepath.Join(ed.prefix, skill)
			if target != expected {
				stale = append(stale, filepath.Join("."+ed.name, "skills", skill))
			}
		}
	}

	if len(stale) == 0 {
		return Check{
			ID:            "local_skill_links",
			Status:        StatusPass,
			Severity:      SeverityInfo,
			RemediationID: RemediationNone,
			Message:       "Engine-local skill links are correct.",
		}
	}

	return Check{
		ID:            "local_skill_links",
		Status:        StatusWarn,
		Severity:      SeverityWarn,
		RemediationID: RemediationRunHalInit,
		Message:       "Stale engine-local skill links: " + strings.Join(stale, ", ") + ". Run hal links refresh.",
		Remediation:   &Remediation{Command: "hal links refresh", Safe: true},
	}
}

func checkLegacySandboxState(halDir string) Check {
	sandboxPath := filepath.Join(halDir, template.SandboxFile)
	if _, err := os.Stat(sandboxPath); os.IsNotExist(err) {
		return Check{
			ID:            "legacy_sandbox_state",
			Status:        StatusPass,
			Severity:      SeverityInfo,
			RemediationID: RemediationNone,
			Message:       "No legacy sandbox state found.",
		}
	}
	return Check{
		ID:            "legacy_sandbox_state",
		Status:        StatusWarn,
		Severity:      SeverityWarn,
		RemediationID: RemediationNone,
		Message:       "Legacy .hal/sandbox.json found — run 'hal sandbox migrate'",
		Remediation:   &Remediation{Command: "hal sandbox migrate", Safe: true},
	}
}

func checkBrokenSkillLinks(dir string) Check {
	// Check project-local engine skill directories for broken symlinks
	engineDirs := []string{
		filepath.Join(dir, ".claude", "skills"),
		filepath.Join(dir, ".pi", "skills"),
	}

	var broken []string
	for _, skillsDir := range engineDirs {
		entries, err := os.ReadDir(skillsDir)
		if err != nil {
			continue // dir may not exist
		}
		for _, entry := range entries {
			linkPath := filepath.Join(skillsDir, entry.Name())
			info, err := os.Lstat(linkPath)
			if err != nil {
				continue
			}
			if info.Mode()&os.ModeSymlink == 0 {
				continue // not a symlink
			}
			// Check if target exists
			if _, err := os.Stat(linkPath); os.IsNotExist(err) {
				rel, _ := filepath.Rel(dir, linkPath)
				if rel == "" {
					rel = linkPath
				}
				broken = append(broken, rel)
			}
		}
	}

	if len(broken) == 0 {
		return Check{
			ID:            "broken_skill_links",
			Status:        StatusPass,
			Severity:      SeverityInfo,
			RemediationID: RemediationNone,
			Message:       "No broken skill symlinks found.",
		}
	}

	return Check{
		ID:            "broken_skill_links",
		Status:        StatusWarn,
		Severity:      SeverityWarn,
		RemediationID: RemediationRunHalInit,
		Message:       "Broken skill symlinks: " + strings.Join(broken, ", ") + ". Run hal links refresh.",
		Remediation:   &Remediation{Command: "hal links clean", Safe: true},
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
