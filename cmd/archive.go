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
var archiveListJSONFlag bool
var archiveCreateJSONFlag bool

// ArchiveCreateResult is the machine-readable output of hal archive create --json.
type ArchiveCreateResult struct {
	ContractVersion int    `json:"contractVersion"`
	OK              bool   `json:"ok"`
	ArchiveDir      string `json:"archiveDir,omitempty"`
	Name            string `json:"name,omitempty"`
	Error           string `json:"error,omitempty"`
	Summary         string `json:"summary"`
}

// ArchiveListResult is the machine-readable output of hal archive list --json.
type ArchiveListResult struct {
	ContractVersion int                   `json:"contractVersion"`
	OK              bool                  `json:"ok"`
	Archives        []archive.ArchiveInfo `json:"archives"`
	Error           string                `json:"error,omitempty"`
	Summary         string                `json:"summary"`
}

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

Use --verbose for detailed output including branch name and full path.
Use --json for machine-readable JSON output.`,
	Example: `  hal archive list
  hal archive list --verbose
  hal archive list --json`,
	RunE: runArchiveList,
}

var archiveRestoreJSONFlag bool

var archiveRestoreCmd = &cobra.Command{
	Use:     "restore <name>",
	Short:   "Restore an archived feature",
	Args:    exactArgsValidation(1),
	PreRunE: disallowArchiveNameFlagOnSubcommands,
	Long: `Restore files from an archive directory back into .hal/.

If there is current feature state, it will be auto-archived first.

The name argument is the archive directory name (e.g., 2026-01-15-my-feature).
Use 'hal archive list' to see available archives.`,
	Example: `  hal archive restore 2026-01-15-checkout-flow
  hal archive restore 2026-01-15-checkout-flow --json`,
	RunE: runArchiveRestore,
}

func init() {
	archiveCmd.Flags().StringVarP(&archiveNameFlag, "name", "n", "", "Archive name (default: derived from branch name)")
	archiveCmd.Flags().BoolVar(&archiveCreateJSONFlag, "json", false, "Output machine-readable JSON result")
	archiveCreateCmd.Flags().StringVarP(&archiveNameFlag, "name", "n", "", "Archive name (default: derived from branch name)")
	archiveCreateCmd.Flags().BoolVar(&archiveCreateJSONFlag, "json", false, "Output machine-readable JSON result")
	archiveListCmd.Flags().StringVarP(&archiveNameFlag, "name", "n", "", "Archive name (default: derived from branch name)")
	archiveRestoreCmd.Flags().StringVarP(&archiveNameFlag, "name", "n", "", "Archive name (default: derived from branch name)")
	if err := archiveListCmd.Flags().MarkHidden("name"); err != nil {
		panic(err)
	}
	if err := archiveRestoreCmd.Flags().MarkHidden("name"); err != nil {
		panic(err)
	}
	archiveListCmd.Flags().BoolVarP(&archiveVerboseFlag, "verbose", "v", false, "Show detailed output")
	archiveListCmd.Flags().BoolVar(&archiveListJSONFlag, "json", false, "Output as JSON")
	archiveRestoreCmd.Flags().BoolVar(&archiveRestoreJSONFlag, "json", false, "Output machine-readable JSON result")

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
	jsonMode := false
	if cmd != nil {
		in = cmd.InOrStdin()
		out = cmd.OutOrStdout()
		if flags := cmd.Flags(); flags != nil && flags.Lookup("json") != nil {
			value, err := flags.GetBool("json")
			if err != nil {
				return err
			}
			jsonMode = value
		}
	}

	if jsonMode {
		return runArchiveCreateJSON(template.HalDir, name, out)
	}

	if strings.TrimSpace(name) == "" && isNonInteractive(in) {
		return exitWithCode(cmd, ExitCodeValidation, fmt.Errorf("archive name is required in non-interactive mode; pass --name/-n"))
	}

	return runArchiveCreate(template.HalDir, name, in, out)
}

func runArchiveCreateJSON(halDir string, name string, out io.Writer) error {
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		jr := ArchiveCreateResult{
			ContractVersion: 1,
			OK:              false,
			Error:           ".hal/ not found",
			Summary:         ".hal/ not found — run hal init first.",
		}
		data, marshalErr := json.MarshalIndent(jr, "", "  ")
		if marshalErr != nil {
			return fmt.Errorf("failed to marshal archive result: %w", marshalErr)
		}
		fmt.Fprintln(out, string(data))
		return fmt.Errorf(".hal/ not found - run 'hal init' first")
	}

	if strings.TrimSpace(name) == "" {
		name = deriveArchiveName(halDir)
	}
	if strings.TrimSpace(name) == "" {
		msg := "archive name is required with --json; pass --name/-n"
		if err := outputArchiveCreateJSONError(out, msg); err != nil {
			return err
		}
		return fmt.Errorf("%s", msg)
	}

	archiveDir, err := archive.Create(halDir, name, io.Discard)
	jr := ArchiveCreateResult{
		ContractVersion: 1,
		Name:            name,
	}
	if err != nil {
		jr.OK = false
		jr.Error = err.Error()
		jr.Summary = "Archive creation failed: " + err.Error()
	} else {
		jr.OK = true
		jr.ArchiveDir = archiveDir
		jr.Summary = fmt.Sprintf("Archived to %s.", archiveDir)
	}

	data, marshalErr := json.MarshalIndent(jr, "", "  ")
	if marshalErr != nil {
		return fmt.Errorf("failed to marshal archive result: %w", marshalErr)
	}
	fmt.Fprintln(out, string(data))
	if err != nil {
		return err
	}
	return nil
}

func outputArchiveCreateJSONError(out io.Writer, msg string) error {
	jr := ArchiveCreateResult{
		ContractVersion: 1,
		OK:              false,
		Error:           msg,
		Summary:         "Archive creation failed: " + msg,
	}
	data, err := json.MarshalIndent(jr, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal archive result: %w", err)
	}
	fmt.Fprintln(out, string(data))
	return nil
}

func runArchiveList(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	jsonMode := false
	if cmd != nil {
		out = cmd.OutOrStdout()
		if flags := cmd.Flags(); flags != nil && flags.Lookup("json") != nil {
			value, err := flags.GetBool("json")
			if err != nil {
				return err
			}
			jsonMode = value
		}
	}
	if jsonMode {
		return runArchiveListJSON(template.HalDir, out)
	}
	return runArchiveListFn(template.HalDir, archiveVerboseFlag, out)
}

func runArchiveListJSON(halDir string, out io.Writer) error {
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return outputArchiveListJSON(out, nil, ".hal/ not found - run 'hal init' first")
	}

	archives, err := archive.List(halDir)
	if err != nil {
		return outputArchiveListJSON(out, nil, err.Error())
	}

	return outputArchiveListJSON(out, archives, "")
}

func outputArchiveListJSON(out io.Writer, archives []archive.ArchiveInfo, msg string) error {
	if archives == nil {
		archives = []archive.ArchiveInfo{}
	}

	jr := ArchiveListResult{
		ContractVersion: 1,
		OK:              msg == "",
		Archives:        archives,
		Summary:         fmt.Sprintf("Listed %d archive(s).", len(archives)),
	}
	if msg != "" {
		jr.Error = msg
		jr.Summary = "Archive listing failed: " + msg
	}

	data, err := json.MarshalIndent(jr, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal archive list result: %w", err)
	}
	fmt.Fprintln(out, string(data))
	if msg != "" {
		return fmt.Errorf("%s", msg)
	}
	return nil
}

func runArchiveRestore(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	jsonMode := false
	if cmd != nil {
		out = cmd.OutOrStdout()
		if flags := cmd.Flags(); flags != nil && flags.Lookup("json") != nil {
			value, err := flags.GetBool("json")
			if err != nil {
				return err
			}
			jsonMode = value
		}
	}
	if jsonMode {
		err := runArchiveRestoreFn(template.HalDir, args[0], io.Discard)
		jr := map[string]interface{}{
			"contractVersion": 1,
			"ok":              err == nil,
			"name":            args[0],
		}
		if err != nil {
			jr["error"] = err.Error()
			jr["summary"] = "Restore failed: " + err.Error()
		} else {
			jr["summary"] = fmt.Sprintf("Restored %s.", args[0])
		}
		data, _ := json.MarshalIndent(jr, "", "  ")
		fmt.Fprintln(out, string(data))
		if err != nil {
			return err
		}
		return nil
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

	formatArchiveListStyled(archives, out, verbose)
	return nil
}

// formatArchiveListStyled renders the archive list with lipgloss styling.
func formatArchiveListStyled(archives []archive.ArchiveInfo, w io.Writer, verbose bool) {
	if len(archives) == 0 {
		fmt.Fprintf(w, "%s No archives found.\n", engine.StyleMuted.Render("○"))
		return
	}

	if verbose {
		fmt.Fprintf(w, "%s\n", engine.StyleBold.Render(
			fmt.Sprintf("%-30s  %-12s  %-10s  %-30s  %s", "NAME", "DATE", "PROGRESS", "BRANCH", "PATH")))
		for _, a := range archives {
			progress := fmt.Sprintf("%d/%d", a.Completed, a.Total)
			fmt.Fprintf(w, "%-30s  %-12s  %-10s  %-30s  %s\n",
				engine.StyleInfo.Render(a.Name), engine.StyleMuted.Render(a.Date),
				progress, engine.StyleMuted.Render(a.BranchName), engine.StyleMuted.Render(a.Dir))
		}
	} else {
		fmt.Fprintf(w, "%s\n", engine.StyleBold.Render(
			fmt.Sprintf("%-30s  %-12s  %s", "NAME", "DATE", "PROGRESS")))
		for _, a := range archives {
			progress := fmt.Sprintf("%d/%d", a.Completed, a.Total)
			fmt.Fprintf(w, "%-30s  %-12s  %s\n",
				engine.StyleInfo.Render(a.Name), engine.StyleMuted.Render(a.Date), progress)
		}
	}
	fmt.Fprintf(w, "\n%s\n", engine.StyleMuted.Render(fmt.Sprintf("%d archive(s)", len(archives))))
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
		fmt.Fprintf(out, "%s [%s]: ", engine.StyleBold.Render("Archive name"), engine.StyleMuted.Render(defaultName))
	} else {
		fmt.Fprintf(out, "%s: ", engine.StyleBold.Render("Archive name"))
	}

	reader := bufio.NewReader(in)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" {
		return defaultName
	}
	return input
}
