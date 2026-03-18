package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/skills"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

var (
	linksJSONFlag   bool
	linksEngineFlag string
)

// LinkStatus describes the state of links for one engine.
type LinkStatus struct {
	Engine     string       `json:"engine"`
	Mode       string       `json:"mode"` // "project_local" or "global"
	SkillsDir  string       `json:"skillsDir"`
	CommandsDir string      `json:"commandsDir,omitempty"`
	Status     string       `json:"status"` // "pass", "warn", "fail", "skip"
	Links      []LinkDetail `json:"links,omitempty"`
	Issues     []string     `json:"issues,omitempty"`
}

// LinkDetail describes a single link.
type LinkDetail struct {
	Name   string `json:"name"`
	Link   string `json:"link"`
	Target string `json:"target"`
	Status string `json:"status"` // "ok", "broken", "stale", "missing"
}

// LinksResult is the machine-readable output of hal links status --json.
type LinksResult struct {
	ContractVersion int          `json:"contractVersion"`
	Healthy         bool         `json:"healthy"`
	Engines         []LinkStatus `json:"engines"`
	Summary         string       `json:"summary"`
}

var linksCmd = &cobra.Command{
	Use:   "links",
	Short: "Manage engine skill links",
	Long: `Inspect and manage skill links between .hal/skills/ and engine directories.

Hal creates symlinks from engine-specific directories to .hal/skills/ so
each AI engine can discover project skills. These links are:

  Project-local:
    .claude/skills/  → .hal/skills/   (Claude Code)
    .pi/skills/      → .hal/skills/   (Pi)

  Global (single-active-repo):
    ~/.codex/skills/  → .hal/skills/  (Codex)

Use 'hal links status' to inspect link health.
Use 'hal links refresh' to recreate all links.`,
	Example: `  hal links status
  hal links status --json
  hal links refresh
  hal links refresh codex`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

var linksStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show link status for all engines",
	Args:  noArgsValidation(),
	Long: `Show the status of skill links for all registered engines.

Checks that symlinks in engine directories point to the correct .hal/skills/ targets.
Use --engine to filter to a specific engine.`,
	Example: `  hal links status
  hal links status --json
  hal links status --engine codex`,
	RunE: runLinksStatus,
}

var linksRefreshCmd = &cobra.Command{
	Use:   "refresh [engine]",
	Short: "Refresh skill links for engines",
	Args:  maxArgsValidation(1),
	Long: `Recreate skill links for all engines, or a specific engine.

This is equivalent to the linking step of 'hal init', but without
touching any other .hal/ files.

Examples:
  hal links refresh          # Refresh all engines
  hal links refresh claude   # Refresh only Claude links
  hal links refresh codex    # Refresh only Codex links`,
	Example: `  hal links refresh
  hal links refresh claude
  hal links refresh codex`,
	RunE: runLinksRefresh,
}

var linksCleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Remove deprecated and broken skill links",
	Args:  noArgsValidation(),
	Long: `Remove deprecated and broken skill links from engine directories.

Removes:
  - .claude/skills/ralph (deprecated alias)
  - .pi/skills/ralph (deprecated alias)
  - Any broken symlinks in engine skill directories

This is a targeted cleanup for link-specific debris.
Use 'hal cleanup' for broader .hal/ file cleanup.`,
	Example: `  hal links clean`,
	RunE:    runLinksClean,
}

func init() {
	linksStatusCmd.Flags().BoolVar(&linksJSONFlag, "json", false, "Output machine-readable JSON")
	linksStatusCmd.Flags().StringVarP(&linksEngineFlag, "engine", "e", "", "Filter to specific engine (claude, pi, codex)")
	linksCmd.AddCommand(linksStatusCmd)
	linksCmd.AddCommand(linksRefreshCmd)
	linksCmd.AddCommand(linksCleanCmd)
	rootCmd.AddCommand(linksCmd)
}

func runLinksStatus(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	jsonMode := linksJSONFlag
	engineFilter := linksEngineFlag
	if cmd != nil {
		out = cmd.OutOrStdout()
		if cmd.Flags().Lookup("json") != nil {
			v, _ := cmd.Flags().GetBool("json")
			jsonMode = v
		}
		if cmd.Flags().Lookup("engine") != nil {
			v, _ := cmd.Flags().GetString("engine")
			engineFilter = strings.ToLower(strings.TrimSpace(v))
		}
	}
	return runLinksStatusFn(".", jsonMode, engineFilter, out)
}

func runLinksStatusFn(dir string, jsonMode bool, engineFilter string, out io.Writer) error {
	absDir, _ := filepath.Abs(dir)
	var engineStatuses []LinkStatus

	// Check each registered engine linker
	for _, name := range []string{"claude", "pi", "codex"} {
		if engineFilter != "" && name != engineFilter {
			continue
		}
		linker := skills.GetLinker(name)
		if linker == nil {
			continue
		}

		es := inspectLinker(absDir, dir, linker)
		engineStatuses = append(engineStatuses, es)
	}

	if jsonMode {
		allOK := true
		for _, es := range engineStatuses {
			if es.Status != "pass" && es.Status != "skip" {
				allOK = false
			}
		}

		result := LinksResult{
			ContractVersion: 1,
			Healthy:         allOK,
			Engines:         engineStatuses,
		}
		if allOK {
			result.Summary = "All engine links are healthy."
		} else {
			result.Summary = "Some engine links need attention. Run hal links refresh."
		}

		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal links status: %w", err)
		}
		fmt.Fprintln(out, string(data))
		return nil
	}

	// Human-readable output
	for _, es := range engineStatuses {
		icon := "✓"
		switch es.Status {
		case "warn":
			icon = "⚠"
		case "fail":
			icon = "✗"
		case "skip":
			icon = "−"
		}
		fmt.Fprintf(out, "  %s  %s (%s)\n", icon, es.Engine, es.Mode)
		fmt.Fprintf(out, "     skills: %s\n", es.SkillsDir)
		if es.CommandsDir != "" {
			fmt.Fprintf(out, "     commands: %s\n", es.CommandsDir)
		}
		if len(es.Issues) > 0 {
			for _, issue := range es.Issues {
				fmt.Fprintf(out, "     ⚠ %s\n", issue)
			}
		}
		fmt.Fprintln(out)
	}

	return nil
}

func inspectLinker(absDir, dir string, linker skills.EngineLinker) LinkStatus {
	name := linker.Name()
	skillsDir := linker.SkillsDir()
	commandsDir := linker.CommandsDir()

	mode := "project_local"
	if name == "codex" {
		mode = "global"
	}

	es := LinkStatus{
		Engine:      name,
		Mode:        mode,
		SkillsDir:   skillsDir,
		CommandsDir: commandsDir,
		Status:      "pass",
	}

	var issues []string

	for _, skill := range skills.ManagedSkillNames {
		var linkPath string
		if mode == "global" {
			linkPath = filepath.Join(skillsDir, skill)
		} else {
			linkPath = filepath.Join(dir, skillsDir, skill)
		}

		info, err := os.Lstat(linkPath)
		detail := LinkDetail{Name: skill, Link: linkPath}

		if os.IsNotExist(err) {
			detail.Status = "missing"
			detail.Target = ""
			issues = append(issues, skill+" link missing")
		} else if err != nil {
			detail.Status = "broken"
			issues = append(issues, skill+": "+err.Error())
		} else if info.Mode()&os.ModeSymlink == 0 {
			detail.Status = "stale"
			issues = append(issues, skill+" is not a symlink")
		} else {
			target, _ := os.Readlink(linkPath)
			detail.Target = target

			// Check target exists
			if _, err := os.Stat(linkPath); os.IsNotExist(err) {
				detail.Status = "broken"
				issues = append(issues, skill+" → broken target: "+target)
			} else {
				detail.Status = "ok"
			}
		}

		es.Links = append(es.Links, detail)
	}

	if len(issues) > 0 {
		es.Status = "warn"
		es.Issues = issues
	}

	return es
}

func runLinksClean(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	if cmd != nil {
		out = cmd.OutOrStdout()
	}
	return runLinksCleanFn(".", out)
}

func runLinksCleanFn(dir string, out io.Writer) error {
	removed := 0

	// Remove deprecated links
	deprecated := []string{
		filepath.Join(dir, ".claude", "skills", "ralph"),
		filepath.Join(dir, ".pi", "skills", "ralph"),
	}
	for _, link := range deprecated {
		if _, err := os.Lstat(link); os.IsNotExist(err) {
			continue
		}
		if err := os.RemoveAll(link); err != nil {
			fmt.Fprintf(out, "  ✗ failed to remove %s: %v\n", link, err)
			continue
		}
		fmt.Fprintf(out, "  ✓ removed %s\n", link)
		removed++
	}

	// Remove broken symlinks from engine skill dirs
	engineDirs := []string{
		filepath.Join(dir, ".claude", "skills"),
		filepath.Join(dir, ".pi", "skills"),
	}
	for _, skillsDir := range engineDirs {
		entries, err := os.ReadDir(skillsDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			linkPath := filepath.Join(skillsDir, entry.Name())
			info, err := os.Lstat(linkPath)
			if err != nil || info.Mode()&os.ModeSymlink == 0 {
				continue
			}
			if _, err := os.Stat(linkPath); os.IsNotExist(err) {
				if err := os.Remove(linkPath); err == nil {
					fmt.Fprintf(out, "  ✓ removed broken link %s\n", linkPath)
					removed++
				}
			}
		}
	}

	if removed == 0 {
		fmt.Fprintln(out, "No deprecated or broken links found.")
	} else {
		fmt.Fprintf(out, "\nCleaned %d link(s).\n", removed)
	}

	return nil
}

func runLinksRefresh(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	if cmd != nil {
		out = cmd.OutOrStdout()
	}

	projectDir := "."

	// Check .hal/skills exists
	halSkillsDir := filepath.Join(projectDir, template.HalDir, "skills")
	if _, err := os.Stat(halSkillsDir); os.IsNotExist(err) {
		return fmt.Errorf(".hal/skills/ not found. Run 'hal init' first")
	}

	if len(args) > 0 {
		// Refresh specific engine
		engineName := strings.ToLower(strings.TrimSpace(args[0]))
		linker := skills.GetLinker(engineName)
		if linker == nil {
			return fmt.Errorf("unknown engine %q (available: claude, pi, codex)", engineName)
		}

		if err := linker.Link(projectDir, skills.ManagedSkillNames); err != nil {
			return fmt.Errorf("failed to refresh %s links: %w", engineName, err)
		}
		if err := linker.LinkCommands(projectDir); err != nil {
			fmt.Fprintf(out, "warning: failed to link commands for %s: %v\n", engineName, err)
		}
		fmt.Fprintf(out, "Refreshed %s skill links.\n", engineName)
		return nil
	}

	// Refresh all engines
	if err := skills.LinkAllEngines(projectDir); err != nil {
		_ = err // warnings logged internally
	}
	if err := skills.LinkAllCommands(projectDir); err != nil {
		_ = err // warnings logged internally
	}
	fmt.Fprintln(out, "Refreshed skill links for all engines.")
	return nil
}
