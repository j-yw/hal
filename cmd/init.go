package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/skills"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

// migrateResult indicates the outcome of a config directory migration.
type migrateResult int

const (
	migrateNone    migrateResult = iota // no migration needed
	migrateDone                         // .goralph was renamed to .hal
	migrateWarning                      // both directories exist
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize .hal/ directory",
	Args:  noArgsValidation(),
	Long: `Initialize the .hal/ directory in the current project.

If an existing .goralph/ directory is detected and no .hal/ directory exists,
it will be automatically renamed to .hal/ to preserve your configuration.

Also adds .hal/ to .gitignore if not already present.

Creates:
  .hal/
    config.yaml    # Configuration settings
    prompt.md      # Agent instructions template
    progress.txt   # Progress log for learnings
    archive/       # Archived runs
    reports/       # Analysis reports for auto mode
    skills/        # PRD and Hal skills
      prd/         # PRD generation skill
      hal/         # PRD-to-JSON conversion skill

Also creates .claude/skills/ with symlinks to .hal/skills/ for Claude Code
skill discovery.

After init, create a prd.json with your user stories and run 'hal run'.
Or use 'hal plan' to interactively generate a PRD.`,
	RunE: runInit,
}

func init() {
	addInitFlags(initCmd)
	rootCmd.AddCommand(initCmd)
}

func addInitFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("refresh-templates", false, "Backup and overwrite core templates with latest embedded versions")
	cmd.Flags().Bool("dry-run", false, "Preview template refresh actions (only applies with --refresh-templates; other init steps still run)")
}

// ensureGitignore configures .gitignore to ignore .hal/ runtime state but allow
// .hal/standards/ and .hal/commands/ to be committed (shared project knowledge).
// Creates .gitignore if it doesn't exist.
func ensureGitignore(projectDir string, w io.Writer) error {
	gitignorePath := filepath.Join(projectDir, ".gitignore")

	// Read existing content (if any)
	content, err := os.ReadFile(gitignorePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read .gitignore: %w", err)
	}

	lines := strings.Split(string(content), "\n")

	hasHalStar := false
	hasStandardsException := false
	hasCommandsException := false
	oldHalIdx := -1

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch trimmed {
		case ".hal/*":
			hasHalStar = true
		case "!.hal/standards/":
			hasStandardsException = true
		case "!.hal/commands/":
			hasCommandsException = true
		case ".hal", ".hal/":
			oldHalIdx = i
		}
	}

	// Already correct
	if hasHalStar && hasStandardsException && hasCommandsException {
		return nil
	}

	// Migrate: add missing exceptions to existing .hal/* pattern
	if hasHalStar && (!hasStandardsException || !hasCommandsException) {
		var additions []string
		if !hasStandardsException {
			additions = append(additions, "!.hal/standards/")
		}
		if !hasCommandsException {
			additions = append(additions, "!.hal/commands/")
		}
		// Insert after .hal/*
		for i, line := range lines {
			if strings.TrimSpace(line) == ".hal/*" {
				rest := append(additions, lines[i+1:]...)
				lines = append(lines[:i+1], rest...)
				break
			}
		}
		newContent := strings.Join(lines, "\n")
		if err := os.WriteFile(gitignorePath, []byte(newContent), 0644); err != nil {
			return fmt.Errorf("failed to update .gitignore: %w", err)
		}
		fmt.Fprintf(w, "  Updated .gitignore: added committable exceptions\n")
		return nil
	}

	// Migrate old pattern (.hal/ → .hal/* with exceptions)
	if oldHalIdx >= 0 {
		lines[oldHalIdx] = ".hal/*\n!.hal/standards/\n!.hal/commands/"
		newContent := strings.Join(lines, "\n")
		if err := os.WriteFile(gitignorePath, []byte(newContent), 0644); err != nil {
			return fmt.Errorf("failed to update .gitignore: %w", err)
		}
		fmt.Fprintf(w, "  Updated .gitignore: .hal/* (standards and commands are committed)\n")
		return nil
	}

	// Add new entries
	halBlock := "# hal runtime config (standards and commands are committed)\n.hal/*\n!.hal/standards/\n!.hal/commands/\n"
	var newContent string
	if len(content) == 0 {
		newContent = halBlock
	} else {
		existing := string(content)
		if !strings.HasSuffix(existing, "\n") {
			existing += "\n"
		}
		newContent = existing + "\n" + halBlock
	}

	if err := os.WriteFile(gitignorePath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to update .gitignore: %w", err)
	}

	fmt.Fprintf(w, "  Added .hal/* to .gitignore (standards and commands are committed)\n")
	return nil
}

func runInit(cmd *cobra.Command, args []string) error {
	return runInitWithWriters(cmd, args, os.Stdout, os.Stderr)
}

func runInitWithWriters(cmd *cobra.Command, args []string, out, errOut io.Writer) error {
	configDir := template.HalDir
	archiveDir := filepath.Join(configDir, "archive")
	reportsDir := filepath.Join(configDir, "reports")
	standardsDir := filepath.Join(configDir, template.StandardsDir)
	projectDir := "."

	// Read flags (cmd may be nil in tests)
	var doRefresh, dryRun bool
	if cmd != nil {
		doRefresh, _ = cmd.Flags().GetBool("refresh-templates")
		dryRun, _ = cmd.Flags().GetBool("dry-run")
	}

	// Auto-migrate .goralph/ to .hal/ if applicable
	if _, err := migrateConfigDir(".goralph", configDir, out); err != nil {
		return err
	}

	// Create directories (MkdirAll is idempotent - won't fail if exists)
	if err := os.MkdirAll(archiveDir, 0755); err != nil {
		return fmt.Errorf("failed to create directories: %w", err)
	}
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		return fmt.Errorf("failed to create reports directory: %w", err)
	}
	if err := os.MkdirAll(standardsDir, 0755); err != nil {
		return fmt.Errorf("failed to create standards directory: %w", err)
	}

	// Refresh templates if requested (backup & overwrite with latest embedded versions)
	var refresh refreshSummary
	if doRefresh {
		var err error
		refresh, err = refreshTemplates(configDir, dryRun, out)
		if err != nil {
			return fmt.Errorf("failed to refresh templates: %w", err)
		}
	}

	// Create default files from templates only if they don't exist
	defaults, defaultNames := sortedDefaultFiles()
	var created, skipped []string
	for _, filename := range defaultNames {
		content := defaults[filename]
		filePath := filepath.Join(configDir, filename)
		if _, err := os.Stat(filePath); err == nil {
			skipped = append(skipped, filename)
			continue
		}
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", filename, err)
		}
		created = append(created, filename)
	}

	// Create .gitkeep in archive only if it doesn't exist
	gitkeepPath := filepath.Join(archiveDir, ".gitkeep")
	if _, err := os.Stat(gitkeepPath); os.IsNotExist(err) {
		if err := os.WriteFile(gitkeepPath, []byte(""), 0644); err != nil {
			return fmt.Errorf("failed to write .gitkeep: %w", err)
		}
	}

	// Create .gitkeep in reports only if it doesn't exist
	reportsGitkeepPath := filepath.Join(reportsDir, ".gitkeep")
	if _, err := os.Stat(reportsGitkeepPath); os.IsNotExist(err) {
		if err := os.WriteFile(reportsGitkeepPath, []byte(""), 0644); err != nil {
			return fmt.Errorf("failed to write reports .gitkeep: %w", err)
		}
	}

	// Add .hal/ to project .gitignore
	if err := ensureGitignore(projectDir, out); err != nil {
		return err
	}

	// Install embedded skills to .hal/skills/
	if err := skills.InstallSkills(projectDir); err != nil {
		return fmt.Errorf("failed to install skills: %w", err)
	}

	// Migrate stale templates (idempotent — safe to run every init)
	if err := migrateTemplates(configDir); err != nil {
		return fmt.Errorf("failed to migrate templates: %w", err)
	}

	// Create symlinks for engine skill discovery
	if err := skills.LinkAllEngines(projectDir); err != nil {
		_ = err // Errors are logged as warnings in LinkAllEngines.
	}

	// Install interactive commands (discover-standards, etc.) to .hal/commands/
	if err := skills.InstallCommands(projectDir); err != nil {
		fmt.Fprintf(errOut, "warning: failed to install commands: %v\n", err)
	}

	// Create symlinks from engine command directories to .hal/commands/
	if err := skills.LinkAllCommands(projectDir); err != nil {
		_ = err // Errors are logged as warnings in LinkAllCommands.
	}

	fmt.Fprintln(out, "Initialized .hal/")
	fmt.Fprintln(out)

	if len(created) > 0 {
		fmt.Fprintln(out, "Created:")
		for _, f := range created {
			fmt.Fprintf(out, "  .hal/%s\n", f)
		}
	}

	if len(skipped) > 0 {
		fmt.Fprintln(out, "Already existed (preserved):")
		for _, f := range skipped {
			fmt.Fprintf(out, "  .hal/%s\n", f)
		}
	}

	refreshChanged := refresh.hasChanges()
	if len(created) == 0 && len(skipped) > 0 && !refreshChanged && !(doRefresh && dryRun) {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "All files already exist. No changes made.")
	} else {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Next steps:")
		fmt.Fprintln(out, "  1. Run: hal plan \"feature description\" to generate a PRD")
		fmt.Fprintln(out, "  2. Or create .hal/prd.json manually")
		fmt.Fprintln(out, "  3. Run: hal run")
	}

	return nil
}

func sortedDefaultFiles() (map[string]string, []string) {
	defaults := template.DefaultFiles()
	names := make([]string, 0, len(defaults))
	for filename := range defaults {
		names = append(names, filename)
	}
	sort.Strings(names)
	return defaults, names
}

// migrateConfigDir checks for a legacy oldDir and migrates it to newDir if applicable.
// Output messages are written to w.
func migrateConfigDir(oldDir, newDir string, w io.Writer) (migrateResult, error) {
	_, oldErr := os.Stat(oldDir)
	_, newErr := os.Stat(newDir)

	oldExists := oldErr == nil
	newExists := newErr == nil

	if oldExists && !newExists {
		// oldDir exists but newDir does not — migrate
		if err := os.Rename(oldDir, newDir); err != nil {
			return migrateNone, fmt.Errorf("failed to migrate %s to %s: %w", oldDir, newDir, err)
		}
		if err := updateMigratedFiles(newDir); err != nil {
			return migrateDone, err
		}
		fmt.Fprintf(w, "Migrated %s/ to %s/ — I've upgraded your configuration. It's going to be a much better experience.\n", oldDir, newDir)
		fmt.Fprintln(w)
		return migrateDone, nil
	}

	if oldExists && newExists {
		// Both exist — warn and use newDir
		fmt.Fprintf(w, "Warning: both %s/ and %s/ exist. Using %s/ — you may want to remove %s/ manually.\n", oldDir, newDir, newDir, oldDir)
		fmt.Fprintln(w)
		return migrateWarning, nil
	}

	return migrateNone, nil
}

func updateMigratedFiles(configDir string) error {
	if err := replaceFileContent(filepath.Join(configDir, template.ConfigFile), func(content string) string {
		return strings.ReplaceAll(content, ".goralph/reports", ".hal/reports")
	}); err != nil {
		return err
	}
	if err := replaceFileContent(filepath.Join(configDir, template.PromptFile), func(content string) string {
		return strings.ReplaceAll(content, ".goralph/", ".hal/")
	}); err != nil {
		return err
	}
	return nil
}

// migrateTemplates applies idempotent fixes to existing .hal/ files.
// This runs on every `hal init` to ensure stale templates pick up fixes.
func migrateTemplates(configDir string) error {
	// Rename dev-browser → agent-browser in all skill files and prompt.md
	devBrowserMigration := func(content string) string {
		return strings.ReplaceAll(content, "dev-browser skill", "agent-browser skill (skip if no dev server running)")
	}

	// Migrate prompt.md
	if err := replaceFileContent(filepath.Join(configDir, template.PromptFile), devBrowserMigration); err != nil {
		return err
	}

	// Migrate skill files
	skillsDir := filepath.Join(configDir, "skills")
	entries, err := os.ReadDir(skillsDir)
	if err != nil {
		return nil // skills dir may not exist yet
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		skillDir := filepath.Join(skillsDir, entry.Name())
		// Walk all files in the skill directory (SKILL.md, examples/*)
		_ = filepath.WalkDir(skillDir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			_ = replaceFileContent(path, devBrowserMigration) // best-effort per file
			return nil
		})
	}

	// Ensure Command Safety section exists in prompt.md
	promptPath := filepath.Join(configDir, template.PromptFile)
	data, err := os.ReadFile(promptPath)
	if err != nil {
		return nil // prompt.md may not exist yet
	}
	if !strings.Contains(string(data), "## Command Safety") {
		if err := replaceFileContent(promptPath, func(content string) string {
			// Insert before Quality Requirements section
			marker := "## Quality Requirements"
			if idx := strings.Index(content, marker); idx >= 0 {
				section := "## Command Safety\n\n" +
					"- Always add timeouts to network commands: `curl --max-time 10`, `timeout 60 <cmd>`\n" +
					"- Never run commands that block indefinitely without a timeout\n" +
					"- Before any browser verification, check if a dev server is running first\n" +
					"- If no server is running, SKIP browser verification — rely on typecheck + build\n" +
					"- Do NOT start long-running servers in the foreground (e.g., `npm run dev` without `&`)\n\n"
				return content[:idx] + section + content[idx:]
			}
			return content
		}); err != nil {
			return err
		}
	}

	// Add {{STANDARDS}} placeholder to prompt.md if missing
	if err := replaceFileContent(filepath.Join(configDir, template.PromptFile), func(content string) string {
		if strings.Contains(content, "{{STANDARDS}}") {
			return content
		}
		old := "You are an autonomous coding agent working on a software project.\n\n## Your Task"
		replacement := "You are an autonomous coding agent working on a software project.\n\n{{STANDARDS}}\n\n## Your Task"
		return strings.Replace(content, old, replacement, 1)
	}); err != nil {
		return err
	}

	// Update branch creation guidance to use {{BASE_BRANCH}} and avoid implicit main.
	if err := replaceFileContent(filepath.Join(configDir, template.PromptFile), func(content string) string {
		canonical := "3. Check you're on the correct branch from PRD `branchName`. If not, check it out or create it from `{{BASE_BRANCH}}` (never default to `main` unless `{{BASE_BRANCH}}` is `main`)."
		variants := []string{
			"3. Check you're on the correct branch from PRD `branchName`. If not, check it out or create from main.",
			"3. Check you're on the correct branch from PRD `branchName`. If not, check it out or create it from main.",
			"3. Check you're on the correct branch from PRD `branchName`. If not, check it out or create from `main`.",
			"3. Check you're on the correct branch from PRD `branchName`. If not, check it out or create from current HEAD.",
			"3. Check you're on the correct branch from PRD `branchName`. If not, check it out or create it from `{{BASE_BRANCH}}`.",
		}
		for _, old := range variants {
			content = strings.ReplaceAll(content, old, canonical)
		}
		return content
	}); err != nil {
		return err
	}

	return nil
}

type refreshSummary struct {
	created   int
	refreshed int
	unchanged int
}

func (s refreshSummary) hasChanges() bool {
	return s.created > 0 || s.refreshed > 0
}

var nowForRefresh = time.Now

func nextBackupName(halDir, filename string) (string, error) {
	timestamp := nowForRefresh().UTC().Format("20060102-150405.000000000")
	for i := 0; i < 1000; i++ {
		name := fmt.Sprintf("%s.%s.bak", filename, timestamp)
		if i > 0 {
			name = fmt.Sprintf("%s.%s.%d.bak", filename, timestamp, i)
		}
		backupPath := filepath.Join(halDir, name)
		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			return name, nil
		} else if err != nil {
			return "", fmt.Errorf("failed to check backup %s: %w", name, err)
		}
	}
	return "", fmt.Errorf("failed to generate unique backup name for %s", filename)
}

// refreshTemplates backs up and overwrites the 3 core templates
// (prompt.md, progress.txt, config.yaml) with the latest embedded versions.
// If dryRun is true, it reports what would happen without modifying files.
// Output is written to w for testability (follows the migrateConfigDir pattern).
func refreshTemplates(halDir string, dryRun bool, w io.Writer) (refreshSummary, error) {
	var summary refreshSummary
	prefix := ""
	if dryRun {
		prefix = "[dry-run] "
	}

	defaults, filenames := sortedDefaultFiles()

	for _, filename := range filenames {
		embedded := defaults[filename]
		filePath := filepath.Join(halDir, filename)
		existing, err := os.ReadFile(filePath)
		if os.IsNotExist(err) {
			if !dryRun {
				if err := os.WriteFile(filePath, []byte(embedded), 0644); err != nil {
					return summary, fmt.Errorf("failed to write %s: %w", filename, err)
				}
			}
			summary.created++
			fmt.Fprintf(w, "  %screated .hal/%s\n", prefix, filename)
			continue
		}
		if err != nil {
			return summary, fmt.Errorf("failed to read %s: %w", filename, err)
		}
		if string(existing) == embedded {
			summary.unchanged++
			fmt.Fprintf(w, "  %sunchanged .hal/%s\n", prefix, filename)
			continue
		}

		// File differs — backup and overwrite.
		backupName, err := nextBackupName(halDir, filename)
		if err != nil {
			return summary, err
		}
		if !dryRun {
			backupPath := filepath.Join(halDir, backupName)
			if err := os.WriteFile(backupPath, existing, 0644); err != nil {
				return summary, fmt.Errorf("failed to backup %s: %w", filename, err)
			}
			if err := os.WriteFile(filePath, []byte(embedded), 0644); err != nil {
				return summary, fmt.Errorf("failed to write %s: %w", filename, err)
			}
		}
		summary.refreshed++
		fmt.Fprintf(w, "  %srefreshed .hal/%s (backup: %s)\n", prefix, filename, backupName)
	}
	return summary, nil
}

func replaceFileContent(path string, transform func(string) string) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", path, err)
	}
	original := string(data)
	updated := transform(original)
	if updated == original {
		return nil
	}
	if err := os.WriteFile(path, []byte(updated), 0644); err != nil {
		return fmt.Errorf("failed to update %s: %w", path, err)
	}
	return nil
}
