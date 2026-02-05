package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/archive"
	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

var archiveNameFlag string
var archiveVerboseFlag bool

var archiveCmd = &cobra.Command{
	Use:   "archive",
	Short: "Archive current feature state",
	Long: `Archive all feature state files from .hal/ into .hal/archive/<date>-<name>/.

Archives: prd.json, prd-*.md, progress.txt, auto-prd.json, auto-state.json,
and reports/* (non-hidden files).

Never touches: config.yaml, prompt.md, skills/, rules/.

Use --name to set the archive name, or you will be prompted interactively.`,
	RunE: runArchive,
}

var archiveListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all archives",
	Long: `List all archived features with date, name, and completion stats.

Use --verbose for detailed output including branch name and full path.`,
	RunE: runArchiveList,
}

var archiveRestoreCmd = &cobra.Command{
	Use:   "restore <name>",
	Short: "Restore an archived feature",
	Long: `Restore files from an archive directory back into .hal/.

If there is current feature state, it will be auto-archived first.

The name argument is the archive directory name (e.g., 2026-01-15-my-feature).
Use 'hal archive list' to see available archives.`,
	Args: cobra.ExactArgs(1),
	RunE: runArchiveRestore,
}

func init() {
	archiveCmd.Flags().StringVar(&archiveNameFlag, "name", "", "Archive name (default: derived from branch name)")
	archiveListCmd.Flags().BoolVarP(&archiveVerboseFlag, "verbose", "v", false, "Show detailed output")

	archiveCmd.AddCommand(archiveListCmd)
	archiveCmd.AddCommand(archiveRestoreCmd)
	rootCmd.AddCommand(archiveCmd)
}

func runArchive(cmd *cobra.Command, args []string) error {
	return runArchiveCreate(template.HalDir, archiveNameFlag, os.Stdin, os.Stdout)
}

func runArchiveList(cmd *cobra.Command, args []string) error {
	return runArchiveListFn(template.HalDir, archiveVerboseFlag, os.Stdout)
}

func runArchiveRestore(cmd *cobra.Command, args []string) error {
	return runArchiveRestoreFn(template.HalDir, args[0], os.Stdout)
}

// runArchiveCreate contains the testable logic for the archive create command.
func runArchiveCreate(halDir string, name string, in io.Reader, out io.Writer) error {
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return fmt.Errorf(".hal/ not found - run 'hal init' first")
	}

	if name == "" {
		defaultName := deriveArchiveName(halDir)
		name = promptForName(defaultName, in, out)
	}

	_, err := archive.Create(halDir, name, out)
	return err
}

// runArchiveListFn contains the testable logic for the archive list command.
func runArchiveListFn(halDir string, verbose bool, out io.Writer) error {
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return fmt.Errorf(".hal/ not found - run 'hal init' first")
	}

	archives, err := archive.List(halDir)
	if err != nil {
		return err
	}

	archive.FormatList(archives, out, verbose)
	return nil
}

// runArchiveRestoreFn contains the testable logic for the archive restore command.
func runArchiveRestoreFn(halDir string, name string, out io.Writer) error {
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return fmt.Errorf(".hal/ not found - run 'hal init' first")
	}

	return archive.Restore(halDir, name, out)
}

// deriveArchiveName attempts to get a default name from prd.json branchName,
// falling back to the current git branch name.
func deriveArchiveName(halDir string) string {
	for _, prdFile := range []string{template.PRDFile, template.AutoPRDFile} {
		data, err := os.ReadFile(filepath.Join(halDir, prdFile))
		if err != nil {
			continue
		}
		var prd engine.PRD
		if err := json.Unmarshal(data, &prd); err != nil {
			continue
		}
		if prd.BranchName != "" {
			return archive.FeatureFromBranch(prd.BranchName)
		}
	}

	// Fall back to current git branch name
	if branch, err := compound.CurrentBranch(); err == nil && branch != "" {
		return archive.FeatureFromBranch(branch)
	}

	return ""
}

// promptForName asks the user for an archive name with a default suggestion.
func promptForName(defaultName string, in io.Reader, out io.Writer) string {
	if defaultName != "" {
		fmt.Fprintf(out, "Archive name [%s]: ", defaultName)
	} else {
		fmt.Fprint(out, "Archive name: ")
	}

	reader := bufio.NewReader(in)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" {
		return defaultName
	}
	return input
}
