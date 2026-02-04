package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/archive"
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

Archives: prd.json, prd-*.md, progress.txt, auto-prd.json, auto-progress.txt,
auto-state.json, and reports/*.md.

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
	halDir := template.HalDir
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return fmt.Errorf(".hal/ not found - run 'hal init' first")
	}

	name := archiveNameFlag
	if name == "" {
		// Try to derive default from prd.json branchName
		defaultName := deriveArchiveName(halDir)
		name = promptForName(defaultName)
	}

	_, err := archive.Create(halDir, name, os.Stdout)
	return err
}

func runArchiveList(cmd *cobra.Command, args []string) error {
	halDir := template.HalDir
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return fmt.Errorf(".hal/ not found - run 'hal init' first")
	}

	archives, err := archive.List(halDir)
	if err != nil {
		return err
	}

	archive.FormatList(archives, os.Stdout, archiveVerboseFlag)
	return nil
}

func runArchiveRestore(cmd *cobra.Command, args []string) error {
	halDir := template.HalDir
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return fmt.Errorf(".hal/ not found - run 'hal init' first")
	}

	return archive.Restore(halDir, args[0], os.Stdout)
}

// deriveArchiveName attempts to get a default name from prd.json branchName.
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
	return ""
}

// promptForName asks the user for an archive name with a default suggestion.
func promptForName(defaultName string) string {
	if defaultName != "" {
		fmt.Printf("Archive name [%s]: ", defaultName)
	} else {
		fmt.Print("Archive name: ")
	}

	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" {
		return defaultName
	}
	return input
}
