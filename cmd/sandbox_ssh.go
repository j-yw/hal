package cmd

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/spf13/cobra"
)

var sandboxSSHCmd = &cobra.Command{
	Use:   "ssh [NAME] [-- command args...]",
	Short: "Open an interactive shell or run a remote command",
	Long: `Open an interactive SSH session to a sandbox, or run a remote command.

With just a name, opens an interactive shell that replaces the current process.
With arguments after --, runs the command in the sandbox and streams output.

When no name is provided, the command auto-resolves:
  - If exactly one sandbox exists, it is selected automatically.
  - If zero sandboxes exist, an error is returned.
  - If multiple exist, an error lists the available choices.

The provider determines the SSH transport.`,
	Example: `  hal sandbox ssh my-sandbox
  hal sandbox ssh my-sandbox -- ls -la
  hal sandbox ssh my-sandbox -- bash -c 'echo hello'
  hal sandbox ssh`,
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSandboxSSH(args, os.Stdout, nil)
	},
}

func init() {
	sandboxCmd.AddCommand(sandboxSSHCmd)
}

// sandboxSSHLoadInstance is injectable for testing.
var sandboxSSHLoadInstance = sandbox.LoadActiveInstance

// sandboxSSHResolveProvider is injectable for testing.
var sandboxSSHResolveProvider = resolveProviderFromGlobalConfig

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

	// Parse args: optional NAME followed by optional [-- command args...]
	name, remoteArgs := parseSSHArgs(args)

	// Resolve target instance from global registry
	instance, hint, err := resolveSSHTarget(name)
	if err != nil {
		return err
	}

	if hint != "" {
		fmt.Fprintln(out, hint)
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
		// Interactive SSH session
		cmd, err := p.SSH(info)
		if err != nil {
			return fmt.Errorf("building SSH command: %w", err)
		}

		if testMode {
			lastSSHCmd = cmd
			return nil
		}

		return execInteractiveSSH(cmd)
	}

	// Remote command execution
	cmd, err := p.Exec(info, remoteArgs)
	if err != nil {
		return fmt.Errorf("building exec command: %w", err)
	}

	if testMode {
		lastSSHCmd = cmd
		return nil
	}

	return sandbox.RunCmd(cmd, out)
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
		return instance, "", nil
	}

	// Legacy project-scoped sandbox state predates lifecycle status and migrates
	// into the registry with a blank status, so SSH treats blank as runnable.
	return sandbox.ResolveDefault(isRunnableSSHTarget)
}

func isRunnableSSHTarget(inst *sandbox.SandboxState) bool {
	if inst == nil {
		return false
	}
	switch strings.TrimSpace(inst.Status) {
	case "", sandbox.StatusRunning:
		return true
	default:
		return false
	}
}
