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

Use --name/-n to set the archive name, or you will be prompted interactively.

'hal archive' is an alias for 'hal archive create'.`,
	Example: `  hal archive
  hal archive --name checkout-flow`,
	RunE: runArchive,
}

var archiveCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Archive current feature state",
	Args:  noArgsValidation(),
	Long: `Archive all feature state files from .hal/ into .hal/archive/<date>-<name>/.

Use --name/-n to set the archive name, or omit it to be prompted interactively.`,
	Example: `  hal archive create
  hal archive create --name checkout-flow`,
	RunE: runArchiveCreateCommand,
}

var archiveListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List all archives",
	Args:    noArgsValidation(),
	PreRunE: disallowArchiveNameFlagOnSubcommands,
	Long: `List all archived features with date, name, and completion stats.

Use --verbose for detailed output including branch name and full path.`,
	Example: `  hal archive list
  hal archive list --verbose`,
	RunE: runArchiveList,
}

var archiveRestoreCmd = &cobra.Command{
	Use:     "restore <name>",
	Short:   "Restore an archived feature",
	Args:    exactArgsValidation(1),
	PreRunE: disallowArchiveNameFlagOnSubcommands,
	Long: `Restore files from an archive directory back into .hal/.

If there is current feature state, it will be auto-archived first.

The name argument is the archive directory name (e.g., 2026-01-15-my-feature).
Use 'hal archive list' to see available archives.`,
	Example: `  hal archive restore 2026-01-15-checkout-flow`,
	RunE:    runArchiveRestore,
}

func init() {
	archiveCmd.Flags().StringVarP(&archiveNameFlag, "name", "n", "", "Archive name (default: derived from branch name)")
	archiveCreateCmd.Flags().StringVarP(&archiveNameFlag, "name", "n", "", "Archive name (default: derived from branch name)")
	archiveListCmd.Flags().StringVarP(&archiveNameFlag, "name", "n", "", "Archive name (default: derived from branch name)")
	archiveRestoreCmd.Flags().StringVarP(&archiveNameFlag, "name", "n", "", "Archive name (default: derived from branch name)")
	if err := archiveListCmd.Flags().MarkHidden("name"); err != nil {
		panic(err)
	}
	if err := archiveRestoreCmd.Flags().MarkHidden("name"); err != nil {
		panic(err)
	}
	archiveListCmd.Flags().BoolVarP(&archiveVerboseFlag, "verbose", "v", false, "Show detailed output")

	archiveCmd.AddCommand(archiveCreateCmd)
	archiveCmd.AddCommand(archiveListCmd)
	archiveCmd.AddCommand(archiveRestoreCmd)
	rootCmd.AddCommand(archiveCmd)
}

func disallowArchiveNameFlagOnSubcommands(cmd *cobra.Command, args []string) error {
	if cmd != nil && cmd.Flags().Changed("name") {
		return exitWithCode(cmd, ExitCodeValidation, fmt.Errorf("--name/-n is only valid with 'hal archive' or 'hal archive create'"))
	}
	return nil
}

func runArchive(cmd *cobra.Command, args []string) error {
	return runParentCommand(cmd, args, func() error {
		return runArchiveCreateWithIO(cmd, archiveNameFlag)
	})
}

func runArchiveCreateCommand(cmd *cobra.Command, args []string) error {
	return runArchiveCreateWithIO(cmd, archiveNameFlag)
}

func runArchiveCreateWithIO(cmd *cobra.Command, name string) error {
	in := io.Reader(os.Stdin)
	out := io.Writer(os.Stdout)
	if cmd != nil {
		in = cmd.InOrStdin()
		out = cmd.OutOrStdout()
	}

	if strings.TrimSpace(name) == "" && isNonInteractive(in) {
		return exitWithCode(cmd, ExitCodeValidation, fmt.Errorf("archive name is required in non-interactive mode; pass --name/-n"))
	}

	return runArchiveCreate(template.HalDir, name, in, out)
}

func runArchiveList(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	if cmd != nil {
		out = cmd.OutOrStdout()
	}
	return runArchiveListFn(template.HalDir, archiveVerboseFlag, out)
}

func runArchiveRestore(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	if cmd != nil {
		out = cmd.OutOrStdout()
	}
	return runArchiveRestoreFn(template.HalDir, args[0], out)
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
