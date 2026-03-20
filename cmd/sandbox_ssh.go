package cmd

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

var sandboxSSHCmd = &cobra.Command{
	Use:                "ssh [-- command args...]",
	Short:              "Open an interactive shell or run a remote command",
	DisableFlagParsing: true,
	Long: `Open an interactive SSH session to the active sandbox, or run a remote command.

With no arguments, opens an interactive shell that replaces the current process.
With arguments after --, runs the command in the sandbox and streams output.

The provider (Daytona or Hetzner) determines the SSH transport.`,
	Example: `  hal sandbox ssh
  hal sandbox ssh -- ls -la
  hal sandbox ssh -- bash -c 'echo hello'`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSandboxSSH(".", args, os.Stdout, nil, false)
	},
}

func init() {
	sandboxCmd.AddCommand(sandboxSSHCmd)
}

// runSandboxSSH contains the testable logic for the sandbox ssh command.
// If provider is nil, it is resolved from state.Provider.
// If testMode is true, returns the exec.Cmd instead of calling syscall.Exec.
func runSandboxSSH(dir string, args []string, out io.Writer, provider sandbox.Provider, testMode bool) error {
	return runSandboxSSHWithDeps(dir, args, out, provider, testMode)
}

// sshResult is returned in test mode to allow inspecting the command that
// would have been executed.
var lastSSHCmd *exec.Cmd

// runSandboxSSHWithDeps contains the testable logic.
func runSandboxSSHWithDeps(dir string, args []string, out io.Writer, provider sandbox.Provider, testMode bool) error {
	halDir := filepath.Join(dir, template.HalDir)

	state, err := sandbox.LoadState(halDir)
	if err != nil {
		return fmt.Errorf("no active sandbox — run `hal sandbox start` first")
	}

	if provider == nil {
		provider, err = resolveProviderFromState(dir, state)
		if err != nil {
			return err
		}
	}

	// Strip leading "--" from args if present
	remoteArgs := stripDashDash(args)

	if len(remoteArgs) == 0 {
		// Interactive SSH session
		cmd, err := provider.SSH(state.Name)
		if err != nil {
			return fmt.Errorf("building SSH command: %w", err)
		}

		if testMode {
			lastSSHCmd = cmd
			return nil
		}

		// Replace process with SSH
		binary, err := exec.LookPath(cmd.Path)
		if err != nil {
			return fmt.Errorf("finding SSH binary: %w", err)
		}
		return syscall.Exec(binary, cmd.Args, os.Environ())
	}

	// Remote command execution
	cmd, err := provider.Exec(state.Name, remoteArgs)
	if err != nil {
		return fmt.Errorf("building exec command: %w", err)
	}

	if testMode {
		lastSSHCmd = cmd
		return nil
	}

	return sandbox.RunCmd(cmd, out)
}

// stripDashDash removes a leading "--" from args if present.
func stripDashDash(args []string) []string {
	if len(args) > 0 && args[0] == "--" {
		return args[1:]
	}
	return args
}
