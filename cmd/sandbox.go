package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var sandboxCmd = &cobra.Command{
	Use:   "sandbox",
	Short: "Manage Daytona sandboxes",
	Long: `Manage Daytona sandbox environments for isolated development.

Subcommands:
  setup       Configure Daytona API credentials
  start       Create and start a sandbox
  stop        Stop a running sandbox
  status      Show sandbox status
  delete      Delete a sandbox
  shell       Open an interactive shell
  exec        Run a command in the sandbox
  snapshot    Manage sandbox snapshots`,
}

var sandboxSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Configure Daytona API credentials",
	Long: `Configure Daytona API key and server URL.

Prompts for API key (masked input) and server URL (with default).
Credentials are saved to the daytona: section of .hal/config.yaml.

Re-running setup overwrites previous credentials.`,
	RunE: runSandboxSetupCobra,
}

func init() {
	sandboxCmd.AddCommand(sandboxSetupCmd)
	rootCmd.AddCommand(sandboxCmd)
}

func runSandboxSetupCobra(cmd *cobra.Command, args []string) error {
	return runSandboxSetup(".", os.Stdin, os.Stdout, readPasswordFromTerminal)
}

// passwordReader reads a password from the user. The fd parameter is the file
// descriptor of the terminal. Returns the password bytes and any error.
type passwordReader func(fd int) ([]byte, error)

// readPasswordFromTerminal reads a password from stdin with echo disabled.
func readPasswordFromTerminal(fd int) ([]byte, error) {
	return term.ReadPassword(fd)
}

// runSandboxSetup contains the testable logic for the sandbox setup command.
// dir is the project root directory (containing .hal/).
func runSandboxSetup(dir string, in io.Reader, out io.Writer, readPassword passwordReader) error {
	halDir := filepath.Join(dir, template.HalDir)

	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return fmt.Errorf(".hal/ not found - run 'hal init' first")
	}

	reader := bufio.NewReader(in)

	// Read API key with masked input
	fmt.Fprint(out, "Daytona API key: ")
	var apiKey string
	if readPassword != nil {
		if f, ok := in.(*os.File); ok {
			pass, err := readPassword(int(f.Fd()))
			fmt.Fprintln(out) // newline after masked input
			if err != nil {
				return fmt.Errorf("reading API key: %w", err)
			}
			apiKey = string(pass)
		} else {
			// Non-terminal input (e.g., tests) — read as plain text
			line, _ := reader.ReadString('\n')
			apiKey = strings.TrimRight(line, "\r\n")
		}
	} else {
		line, _ := reader.ReadString('\n')
		apiKey = strings.TrimRight(line, "\r\n")
	}

	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return fmt.Errorf("API key must not be empty")
	}

	// Read server URL with default
	defaultURL := "https://app.daytona.io/api"
	fmt.Fprintf(out, "Server URL [%s]: ", defaultURL)
	line, _ := reader.ReadString('\n')
	serverURL := strings.TrimSpace(strings.TrimRight(line, "\r\n"))
	if serverURL == "" {
		serverURL = defaultURL
	}

	// Save to config
	cfg := &compound.DaytonaConfig{
		APIKey:    apiKey,
		ServerURL: serverURL,
	}
	if err := compound.SaveConfig(dir, cfg); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	fmt.Fprintln(out, "Daytona credentials saved to .hal/config.yaml")
	return nil
}
