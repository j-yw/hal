package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	display "github.com/jywlabs/hal/internal/engine"
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
	Example: `  hal standards list
  hal standards discover`,
}

var standardsListJSONFlag bool

var standardsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured standards",
	Args:  noArgsValidation(),
	Long: `Show all standards currently configured for this project.

Reads .hal/standards/index.yml and displays the catalog of standards
organized by domain. If no index exists, lists the .md files found.

With --json, outputs standards count and index as JSON.`,
	Example: `  hal standards list
  hal standards list --json`,
	RunE: runStandardsList,
}

var standardsDiscoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Discover and document standards from your codebase",
	Args:  noArgsValidation(),
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
	Example: `  hal standards discover`,
	RunE:    runStandardsDiscover,
}

func init() {
	standardsListCmd.Flags().BoolVar(&standardsListJSONFlag, "json", false, "Output as JSON")
	standardsCmd.AddCommand(standardsListCmd)
	standardsCmd.AddCommand(standardsDiscoverCmd)
	rootCmd.AddCommand(standardsCmd)
}

func runStandardsList(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	if cmd != nil {
		out = cmd.OutOrStdout()
	}
	if standardsListJSONFlag {
		return runStandardsListJSON(template.HalDir, out)
	}
	return runStandardsListFn(template.HalDir, out)
}

func runStandardsListJSON(halDir string, out io.Writer) error {
	count, _ := standards.Count(halDir)
	index, _ := standards.ListIndex(halDir)

	result := map[string]interface{}{
		"count": count,
	}
	if index != "" {
		result["index"] = index
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal standards: %w", err)
	}
	fmt.Fprintln(out, string(data))
	return nil
}

func runStandardsListFn(halDir string, w io.Writer) error {
	// Check if standards directory exists
	standardsDir := filepath.Join(halDir, template.StandardsDir)
	if _, err := os.Stat(standardsDir); os.IsNotExist(err) {
		fmt.Fprintf(w, "%s No standards directory found.\n", display.StyleWarning.Render("[!]"))
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Run %s first, then use %s to create standards.\n",
			display.StyleInfo.Render("hal init"), display.StyleInfo.Render("hal standards discover"))
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
		fmt.Fprintf(w, "%s No standards found in .hal/standards/\n", display.StyleWarning.Render("[!]"))
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Run %s to extract standards from your codebase.\n",
			display.StyleInfo.Render("hal standards discover"))
		return nil
	}

	fmt.Fprintf(w, "%s %s\n", display.StyleTitle.Render("Standards:"), display.StyleBold.Render(fmt.Sprintf("%d files", count)))
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
	fmt.Fprintf(w, "%s\n", display.StyleMuted.Render("Standards are injected into every 'hal run' iteration automatically."))
	return nil
}

func runStandardsDiscover(cmd *cobra.Command, args []string) error {
	return runStandardsDiscoverFn(template.HalDir, os.Stdout)
}

func runStandardsDiscoverFn(halDir string, w io.Writer) error {
	// Check init
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		fmt.Fprintf(w, "%s No .hal/ directory found. Run %s first.\n",
			display.StyleWarning.Render("[!]"), display.StyleInfo.Render("hal init"))
		return nil
	}

	fmt.Fprintf(w, "%s\n", display.StyleBold.Render("Standards discovery requires an interactive agent session."))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Use one of the following:")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", display.StyleBold.Render("Claude Code:"))
	fmt.Fprintf(w, "    %s\n", display.StyleInfo.Render("/hal/discover-standards"))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", display.StyleBold.Render("Pi:"))
	fmt.Fprintln(w, "    Load the discover-standards skill and run interactively")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", display.StyleBold.Render("Codex:"))
	fmt.Fprintln(w, "    Ask the agent to read .hal/commands/discover-standards.md")
	fmt.Fprintln(w, "    and follow the process described there")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "The discovery flow will:")
	fmt.Fprintf(w, "  1. %s\n", "Scan your codebase and identify focus areas")
	fmt.Fprintf(w, "  2. %s\n", "Present patterns found in each area")
	fmt.Fprintf(w, "  3. %s\n", "Walk through each standard: ask → draft → confirm → save")
	fmt.Fprintf(w, "  4. %s\n", "Update .hal/standards/index.yml")
	fmt.Fprintln(w)

	count, _ := standards.Count(halDir)
	if count > 0 {
		fmt.Fprintf(w, "%s You currently have %d standard(s) configured.\n",
			display.StyleSuccess.Render("✓"), count)
	} else {
		fmt.Fprintf(w, "%s\n", display.StyleMuted.Render("No standards configured yet. Discovery will create your first ones."))
	}

	return nil
}
