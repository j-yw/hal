package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"strings"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/spf13/cobra"
)

var factoryOpenCmd = &cobra.Command{
	Use:   "open <run-id>",
	Short: "Open handoff guidance for a factory run",
	Args:  exactArgsValidation(1),
	Long: `Open handoff guidance for one stored factory run from the global factory
store.

By default this command prints the best inspection, takeover, or resume command
without executing it. Failed sandbox runs point to the sandbox SSH command.
Failed local runs show repository context and resume guidance when saved auto
state permits continuation. Pass --exec to execute only the generated safe Hal
command.`,
	Example: `  hal factory open run-20260620-001
  hal factory open run-20260620-001 --exec`,
	RunE: runFactoryOpen,
}

type factoryOpenDeps struct {
	defaultStore func() (factory.Store, error)
	execute      func(context.Context, factoryOpenExecRequest) error
}

type factoryOpenExecRequest struct {
	Dir    string
	Args   []string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

var defaultFactoryOpenDeps = factoryOpenDeps{
	defaultStore: factory.DefaultStore,
	execute:      executeFactoryOpenCommand,
}

func runFactoryOpen(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	in := io.Reader(os.Stdin)
	errOut := io.Writer(os.Stderr)
	ctx := context.Background()
	execMode := factoryOpenExecFlag

	if cmd != nil {
		out = cmd.OutOrStdout()
		in = cmd.InOrStdin()
		errOut = cmd.ErrOrStderr()
		if cmd.Context() != nil {
			ctx = cmd.Context()
		}
		if cmd.Flags().Lookup("exec") != nil {
			value, err := cmd.Flags().GetBool("exec")
			if err != nil {
				return err
			}
			execMode = value
		}
	}

	return runFactoryOpenWithDeps(ctx, in, out, errOut, args[0], execMode, defaultFactoryOpenDeps)
}

func runFactoryOpenWithDeps(ctx context.Context, in io.Reader, out io.Writer, errOut io.Writer, runID string, execMode bool, deps factoryOpenDeps) error {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = io.Discard
	}
	if errOut == nil {
		errOut = io.Discard
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if deps.defaultStore == nil {
		return fmt.Errorf("factory store dependency is required")
	}
	if execMode && deps.execute == nil {
		return fmt.Errorf("factory open execute dependency is required")
	}

	store, err := deps.defaultStore()
	if err != nil {
		return fmt.Errorf("open factory store: %w", err)
	}
	summary, err := factory.LoadHandoffSummary(store, runID)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("factory run %q not found", runID)
	}
	if err != nil {
		return err
	}

	renderFactoryOpenOutput(out, summary)
	if !execMode {
		return nil
	}

	req, err := factoryOpenExecRequestFromSummary(summary, in, out, errOut)
	if err != nil {
		return err
	}
	return deps.execute(ctx, req)
}

func renderFactoryOpenOutput(out io.Writer, summary *factory.HandoffSummary) {
	if summary == nil {
		return
	}
	fmt.Fprintf(out, "Run ID: %s\n", summary.RunID)
	fmt.Fprintf(out, "Status: %s\n", summary.Status)
	renderFactoryHandoffDetails(out, summary)
}

func renderFactoryHandoffDetails(out io.Writer, summary *factory.HandoffSummary) {
	if summary == nil {
		return
	}
	fmt.Fprintf(out, "Handoff required: %t\n", summary.HandoffRequired)
	if !summary.HandoffRequired {
		fmt.Fprintln(out, "Handoff: no takeover required.")
		if command := strings.TrimSpace(summary.InspectCommand); command != "" {
			fmt.Fprintf(out, "Inspection command: %s\n", command)
		}
		renderFactoryHandoffLocations(out, "Artifacts", summary.ArtifactLocations)
		renderFactoryHandoffLocations(out, "Logs", summary.LogLocations)
		return
	}

	if summary.SandboxName != "" {
		fmt.Fprintf(out, "Sandbox: %s\n", summary.SandboxName)
	}
	if summary.RepoPath != "" {
		fmt.Fprintf(out, "Repo path: %s\n", summary.RepoPath)
	}
	if summary.BranchName != "" {
		fmt.Fprintf(out, "Branch: %s\n", summary.BranchName)
	}
	if summary.PullRequestURL != "" {
		fmt.Fprintf(out, "PR URL: %s\n", summary.PullRequestURL)
	}
	if summary.CurrentStep != "" {
		fmt.Fprintf(out, "Current step: %s\n", summary.CurrentStep)
	}
	if summary.FailureReason != "" {
		fmt.Fprintf(out, "Failure reason: %s\n", summary.FailureReason)
	}
	if summary.NextAction != nil && strings.TrimSpace(summary.NextAction.Command) != "" {
		fmt.Fprintf(out, "Suggested command: %s\n", summary.NextAction.Command)
		fmt.Fprintf(out, "Action: %s\n", summary.NextAction.Type)
	} else if command := strings.TrimSpace(summary.InspectCommand); command != "" {
		fmt.Fprintf(out, "Suggested command: %s\n", command)
	}
	renderFactoryHandoffLocations(out, "Artifacts", summary.ArtifactLocations)
	renderFactoryHandoffLocations(out, "Logs", summary.LogLocations)
}

func renderFactoryHandoffLocations(out io.Writer, label string, locations []factory.NextActionLocation) {
	if len(locations) == 0 {
		return
	}
	fmt.Fprintf(out, "%s:\n", label)
	for _, location := range locations {
		name := strings.TrimSpace(location.Name)
		path := strings.TrimSpace(location.Path)
		storedPath := strings.TrimSpace(location.StoredPath)
		display := path
		if display == "" {
			display = storedPath
		}
		if display == "" {
			continue
		}
		if name == "" {
			name = "location"
		}
		if storedPath != "" && storedPath != display {
			fmt.Fprintf(out, "  - %s: %s (stored: %s)\n", name, display, storedPath)
			continue
		}
		fmt.Fprintf(out, "  - %s: %s\n", name, display)
	}
}

func factoryOpenExecRequestFromSummary(summary *factory.HandoffSummary, in io.Reader, out io.Writer, errOut io.Writer) (factoryOpenExecRequest, error) {
	if summary == nil {
		return factoryOpenExecRequest{}, fmt.Errorf("factory run %q has no executable handoff action", handoffRunID(summary))
	}
	command := ""
	if summary.NextAction != nil {
		command = strings.TrimSpace(summary.NextAction.Command)
	}
	if command == "" {
		command = strings.TrimSpace(summary.InspectCommand)
	}
	if command == "" {
		return factoryOpenExecRequest{}, fmt.Errorf("factory run %q has no executable handoff action", handoffRunID(summary))
	}
	args, err := factoryOpenCommandArgs(command, summary.RunID)
	if err != nil {
		return factoryOpenExecRequest{}, err
	}
	return factoryOpenExecRequest{
		Dir:    factoryOpenCommandDir(summary),
		Args:   args,
		Stdin:  in,
		Stdout: out,
		Stderr: errOut,
	}, nil
}

func handoffRunID(summary *factory.HandoffSummary) string {
	if summary == nil {
		return ""
	}
	return summary.RunID
}

func factoryOpenCommandDir(summary *factory.HandoffSummary) string {
	if summary == nil || summary.NextAction == nil {
		return ""
	}
	if summary.NextAction.Type == factory.NextActionTypeContinue {
		return strings.TrimSpace(summary.RepoPath)
	}
	return ""
}

func factoryOpenCommandArgs(command string, runID string) ([]string, error) {
	args := strings.Fields(strings.TrimSpace(command))
	if len(args) == 0 {
		return nil, fmt.Errorf("handoff command is empty")
	}
	if len(args) == 4 && args[0] == "hal" && args[1] == "sandbox" && args[2] == "ssh" && args[3] != "" {
		return args, nil
	}
	if len(args) == 3 && args[0] == "hal" && args[1] == "auto" && args[2] == "--resume" {
		return args, nil
	}
	if len(args) == 5 && args[0] == "hal" && args[1] == "factory" && args[2] == "status" && args[3] == runID && args[4] == "--json" {
		return args, nil
	}
	return nil, fmt.Errorf("handoff command %q is not executable by hal factory open", command)
}

func executeFactoryOpenCommand(ctx context.Context, req factoryOpenExecRequest) error {
	if len(req.Args) == 0 {
		return fmt.Errorf("handoff command is empty")
	}
	cmd := exec.CommandContext(ctx, req.Args[0], req.Args[1:]...)
	if strings.TrimSpace(req.Dir) != "" {
		cmd.Dir = req.Dir
	}
	cmd.Stdin = req.Stdin
	cmd.Stdout = req.Stdout
	cmd.Stderr = req.Stderr
	return cmd.Run()
}
