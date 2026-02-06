package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/standards"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

var standardsCmd = &cobra.Command{
	Use:   "standards",
	Short: "Manage project standards",
	Long: `Manage project-specific standards that guide AI agents during hal run.

Standards are concise, codebase-specific rules stored in .hal/standards/.
They are automatically injected into the agent prompt on every hal run iteration,
ensuring consistent code quality and pattern adherence.

Use 'hal standards discover' to interactively extract standards from your codebase.
Use 'hal standards list' to see what's currently configured.`,
}

var standardsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured standards",
	Long: `Show all standards currently configured for this project.

Reads .hal/standards/index.yml and displays the catalog of standards
organized by domain. If no index exists, lists the .md files found.`,
	RunE: runStandardsList,
}

var standardsDiscoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Discover and document standards from your codebase",
	Long: `Interactively discover tribal knowledge and coding patterns from your codebase
and document them as standards.

This command guides you to use your AI agent's interactive mode to run the
discover-standards skill, which walks through your codebase area by area,
identifies patterns, and creates standard files in .hal/standards/.

After running 'hal init', the discover-standards command is available in:
  Claude Code:  /hal/discover-standards
  Pi:           Load the discover skill from .hal/skills/

The discovery flow:
  1. Scans your codebase and identifies focus areas
  2. Presents findings for each area
  3. For each standard: asks why, drafts, confirms, writes
  4. Updates the index`,
	RunE: runStandardsDiscover,
}

func init() {
	standardsCmd.AddCommand(standardsListCmd)
	standardsCmd.AddCommand(standardsDiscoverCmd)
	rootCmd.AddCommand(standardsCmd)
}

func runStandardsList(cmd *cobra.Command, args []string) error {
	return runStandardsListFn(template.HalDir, os.Stdout)
}

func runStandardsListFn(halDir string, w io.Writer) error {
	// Check if standards directory exists
	standardsDir := filepath.Join(halDir, template.StandardsDir)
	if _, err := os.Stat(standardsDir); os.IsNotExist(err) {
		fmt.Fprintln(w, "No standards directory found.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Run 'hal init' first, then use 'hal standards discover' to create standards.")
		return nil
	}

	// Try to read index
	index, err := standards.ListIndex(halDir)
	if err != nil {
		return err
	}

	count, err := standards.Count(halDir)
	if err != nil {
		return err
	}

	if count == 0 {
		fmt.Fprintln(w, "No standards found in .hal/standards/")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Run 'hal standards discover' to extract standards from your codebase.")
		return nil
	}

	fmt.Fprintf(w, "Standards: %d files\n", count)
	fmt.Fprintln(w)

	if index != "" {
		// Strip the header line if present
		lines := strings.Split(strings.TrimSpace(index), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "#") {
				continue // skip YAML comments and markdown headers
			}
			fmt.Fprintf(w, "  %s\n", line)
		}
	} else {
		// No index — list files directly
		fmt.Fprintln(w, "  (no index.yml — showing files)")
		fmt.Fprintln(w)
		err := filepath.WalkDir(standardsDir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			if filepath.Ext(path) != ".md" {
				return nil
			}
			rel, _ := filepath.Rel(standardsDir, path)
			fmt.Fprintf(w, "  %s\n", filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			return err
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Standards are injected into every 'hal run' iteration automatically.")
	return nil
}

func runStandardsDiscover(cmd *cobra.Command, args []string) error {
	return runStandardsDiscoverFn(template.HalDir, os.Stdout)
}

func runStandardsDiscoverFn(halDir string, w io.Writer) error {
	// Check init
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		fmt.Fprintln(w, "No .hal/ directory found. Run 'hal init' first.")
		return nil
	}

	fmt.Fprintln(w, "Standards discovery requires an interactive agent session.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Use one of the following:")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Claude Code:")
	fmt.Fprintln(w, "    /hal/discover-standards")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Pi:")
	fmt.Fprintln(w, "    Load the discover-standards skill and run interactively")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Codex:")
	fmt.Fprintln(w, "    Ask the agent to read .hal/commands/discover-standards.md")
	fmt.Fprintln(w, "    and follow the process described there")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "The discovery flow will:")
	fmt.Fprintln(w, "  1. Scan your codebase and identify focus areas")
	fmt.Fprintln(w, "  2. Present patterns found in each area")
	fmt.Fprintln(w, "  3. Walk through each standard: ask → draft → confirm → save")
	fmt.Fprintln(w, "  4. Update .hal/standards/index.yml")
	fmt.Fprintln(w)

	count, _ := standards.Count(halDir)
	if count > 0 {
		fmt.Fprintf(w, "You currently have %d standard(s) configured.\n", count)
	} else {
		fmt.Fprintln(w, "No standards configured yet. Discovery will create your first ones.")
	}

	return nil
}
