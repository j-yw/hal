package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os/exec"
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/spf13/cobra"
)

var sandboxSSHCmd = &cobra.Command{
	Use:   "ssh [NAME] [-- command args...]",
	Short: "Open an interactive shell or run a remote command",
	Long: `Open an interactive SSH session to a sandbox, or run a remote command.

With just a name, opens an interactive shell that replaces the current process
for provider-backed sandboxes. Worker-backed sandboxes require a command after
-- because the sandboxd transport does not provide an interactive PTY.
With arguments after --, runs the command in the sandbox. Provider SSH streams
output; worker-backed commands return bounded stdout and stderr after completion
and may be truncated at worker protocol limits.

When no name is provided, the command auto-resolves:
  - If exactly one sandbox exists, it is selected automatically.
  - If zero sandboxes exist, an error is returned.
  - If multiple exist, an error lists the available choices.

The sandbox host determines whether Hal uses provider SSH or sandboxd runtime exec.

Hal redacts addresses from its own connection messages and noninteractive
command output by default. Once an interactive shell starts, remote programs
can still print raw network addresses.`,
	Example: `  hal sandbox ssh my-sandbox
  hal sandbox ssh my-sandbox -- ls -la
  hal sandbox ssh local-worker-check -- sh -lc 'echo ready'
  hal sandbox ssh my-sandbox -- bash -c 'echo hello'
  hal sandbox ssh`,
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if isSandboxSSHHelpRequest(args) {
			return cmd.Help()
		}
		return runSandboxCobra(cmd, "Sandbox SSH failed", func() error {
			return runSandboxSSH(args, cmd.OutOrStdout(), nil)
		})
	},
}

func init() {
	sandboxCmd.AddCommand(sandboxSSHCmd)
}

func isSandboxSSHHelpRequest(args []string) bool {
	if len(args) == 0 {
		return false
	}
	return args[0] == "-h" || args[0] == "--help"
}

// sandboxSSHLoadInstance is injectable for testing.
var sandboxSSHLoadInstance = sandbox.LoadActiveInstance

// sandboxSSHResolveProvider is injectable for testing.
var sandboxSSHResolveProvider = func(providerName string) (sandbox.Provider, error) {
	return resolveStoredProviderWithFallback(".", providerName)
}

// sandboxSSHResolveRuntime resolves worker-backed runtime drivers for command execution.
var sandboxSSHResolveRuntime = func(target *sandbox.SandboxState) (sandboxruntime.Driver, error) {
	return resolveFactoryStoredSandboxRuntime(".", target)
}

// sshResult is returned in test mode to allow inspecting the command that
// would have been executed.
var lastSSHCmd *exec.Cmd

// runSandboxSSH is the public entry point for the sandbox ssh command.
func runSandboxSSH(args []string, out io.Writer, provider sandbox.Provider) error {
	return runSandboxSSHWithDeps(args, out, provider, false)
}

// runSandboxSSHWithDeps contains the testable logic for the sandbox ssh command.
// It resolves a target from the global registry, builds ConnectInfo, and dispatches
// to SSH or Exec depending on whether remote command args are present.
func runSandboxSSHWithDeps(args []string, out io.Writer, provider sandbox.Provider, testMode bool) error {
	if err := runSandboxAutoMigrate(".", out); err != nil {
		return err
	}
	showAddresses, args := parseSandboxSSHControlFlags(args)

	// Parse args: optional NAME followed by optional [-- command args...]
	name, remoteArgs := parseSSHArgs(args)

	// Resolve target instance from global registry
	instance, hint, err := resolveSSHTarget(name)
	if err != nil {
		return err
	}

	redactor := sandboxRedactor(showAddresses || sandboxShowAddresses, nil, instance)
	safeOut := sandboxRedactingWriter(out, redactor)
	defer sandboxFlushRedactor(safeOut)
	renderOut := io.Writer(safeOut)
	if renderOut == nil {
		renderOut = out
	}

	if hint != "" {
		fmt.Fprintln(renderOut, hint)
	}
	if sandboxTargetUsesWorkerHost(instance) {
		if len(remoteArgs) == 0 {
			return fmt.Errorf("interactive shell is not supported for worker-backed sandbox %q; pass a command after --, for example: hal sandbox ssh %s -- sh", instance.Name, instance.Name)
		}
		driver, resolveErr := sandboxSSHResolveRuntime(instance)
		if resolveErr != nil {
			return sandboxSanitizeError(fmt.Errorf("resolving runtime for %q: %w", instance.Name, resolveErr), redactor)
		}
		if driver == nil {
			return fmt.Errorf("resolving runtime for %q: sandbox runtime driver is required", instance.Name)
		}
		fmt.Fprintf(renderOut, "Running command on %s via sandboxd worker...\n", instance.Name)
		result, execErr := driver.Exec(context.Background(), sandboxruntime.ExecRequest{
			Target: sandboxRuntimeTargetFromState(instance),
			Args:   append([]string(nil), remoteArgs...),
			Stdout: renderOut,
			Stderr: renderOut,
		})
		if execErr != nil {
			safeErr := sandboxSanitizeError(execErr, redactor)
			if result != nil && result.ExitCode > 0 {
				return &ExitCodeError{Code: result.ExitCode, Err: safeErr}
			}
			return safeErr
		}
		if result == nil {
			return fmt.Errorf("sandbox runtime returned no exec result")
		}
		if result.ExitCode > 0 {
			return &ExitCodeError{Code: result.ExitCode, Err: fmt.Errorf("sandbox command exited with code %d", result.ExitCode)}
		}
		if result.ExitCode < 0 {
			return fmt.Errorf("sandbox command failed before an exit code was available")
		}
		return nil
	}

	// Build ConnectInfo with preferred IP
	info := sandbox.ConnectInfoFromState(instance)

	// Resolve provider if not injected
	p := provider
	if p == nil {
		p, err = sandboxSSHResolveProvider(instance.Provider)
		if err != nil {
			return fmt.Errorf("resolving provider for %q: %w", instance.Name, err)
		}
	}

	if len(remoteArgs) == 0 {
		fmt.Fprintf(renderOut, "Connecting to %s via %s...\n", instance.Name, sandboxAccessLabel(instance))
		// Interactive SSH session
		cmd, err := p.SSH(info)
		if err != nil {
			return sandboxSanitizeError(fmt.Errorf("building SSH command: %w", err), redactor)
		}

		if testMode {
			lastSSHCmd = cmd
			return nil
		}

		sandboxFlushRedactor(safeOut)
		return execInteractiveSSH(cmd)
	}

	fmt.Fprintf(renderOut, "Running command on %s via %s...\n", instance.Name, sandboxAccessLabel(instance))
	// Remote command execution
	cmd, err := p.Exec(info, remoteArgs)
	if err != nil {
		return sandboxSanitizeError(fmt.Errorf("building exec command: %w", err), redactor)
	}

	if testMode {
		lastSSHCmd = cmd
		return nil
	}

	err = sandbox.RunCmd(cmd, renderOut)
	return sandboxSanitizeError(err, redactor)
}

func parseSandboxSSHControlFlags(args []string) (bool, []string) {
	if len(args) == 0 {
		return false, args
	}
	show := false
	out := make([]string, 0, len(args))
	for i, arg := range args {
		if arg == "--" {
			out = append(out, args[i:]...)
			return show, out
		}
		if arg == "--show-addresses" {
			show = true
			continue
		}
		out = append(out, args[i:]...)
		return show, out
	}
	return show, out
}

// parseSSHArgs separates the optional sandbox name from remote command args.
// The first arg before "--" is treated as the sandbox name unless it starts
// with "-" (a flag-like token). Everything after "--" is the remote command.
// Without "--", any remaining args after the name are treated as the remote
// command for convenience.
//
// Examples:
//
//	[]                         → name="", remoteArgs=nil
//	["my-sandbox"]             → name="my-sandbox", remoteArgs=nil
//	["my-sandbox", "--", "ls"] → name="my-sandbox", remoteArgs=["ls"]
//	["my-sandbox", "ls", "-la"] → name="my-sandbox", remoteArgs=["ls", "-la"]
//	["--", "ls"]               → name="", remoteArgs=["ls"]
func parseSSHArgs(args []string) (string, []string) {
	if len(args) == 0 {
		return "", nil
	}

	// Find the position of "--"
	dashIdx := -1
	for i, a := range args {
		if a == "--" {
			dashIdx = i
			break
		}
	}

	var name string
	var remoteArgs []string

	if dashIdx == -1 {
		// No "--" found; first non-flag arg is the name and any trailing args
		// are treated as the remote command.
		if len(args) > 0 && !isFlag(args[0]) {
			name = args[0]
			if len(args) > 1 {
				remoteArgs = args[1:]
			}
		}
	} else {
		// Everything before "--" may contain the name
		if dashIdx > 0 && !isFlag(args[0]) {
			name = args[0]
		}
		// Everything after "--" is the remote command
		if dashIdx+1 < len(args) {
			remoteArgs = args[dashIdx+1:]
		}
	}

	return name, remoteArgs
}

// isFlag returns true if the arg looks like a flag (starts with "-").
func isFlag(arg string) bool {
	return len(arg) > 0 && arg[0] == '-'
}

// resolveSSHTarget resolves a sandbox from the global registry.
// If name is provided, loads that specific instance.
// If name is empty, auto-resolves using ResolveDefault with a running-only filter.
func resolveSSHTarget(name string) (*sandbox.SandboxState, string, error) {
	if name != "" {
		instance, err := sandboxSSHLoadInstance(name)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, "", fmt.Errorf("sandbox %q not found in registry: %w", name, err)
			}
			return nil, "", fmt.Errorf("load sandbox %q: %w", name, err)
		}
		if !isRunnableSSHTarget(instance) {
			return nil, "", fmt.Errorf("sandbox %q is not running", name)
		}
		return instance, "", nil
	}

	instance, hint, err := sandbox.ResolveDefault(isRunnableSSHTarget)
	if err != nil {
		return nil, "", err
	}
	return instance, hint, nil
}

func isRunnableSSHTarget(inst *sandbox.SandboxState) bool {
	if inst == nil {
		return false
	}
	switch strings.TrimSpace(inst.Status) {
	case sandbox.StatusRunning:
		return true
	default:
		return false
	}
}
