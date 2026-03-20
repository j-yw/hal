package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

var sandboxStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Create and start a sandbox",
	Args:  noArgsValidation(),
	Long: `Create and start a Daytona sandbox.

The sandbox name defaults to the current git branch (with slashes replaced by hyphens).
Use --name to override the default name.

Environment variables can be passed with -e/--env (format: KEY=VALUE).
Multiple -e flags are supported. These are injected into the sandbox at runtime.

hal always starts from the template snapshot "hal".
If "hal" does not exist, it is created from sandbox/Dockerfile with context ".".`,
	Example: `  hal sandbox start
  hal sandbox start --name hal-dev
  hal sandbox start -n dev -e TAILSCALE_AUTHKEY=tskey-auth-xxx -e ANTHROPIC_API_KEY=sk-ant-xxx`,
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		envSlice, _ := cmd.Flags().GetStringArray("env")
		envVars := parseEnvFlags(envSlice)
		return runSandboxStartWithDeps(".", name, envVars, os.Stdout, nil, nil, nil, nil)
	},
}

func init() {
	sandboxStartCmd.Flags().StringP("name", "n", "", "sandbox name (defaults to current git branch)")
	sandboxStartCmd.Flags().StringArrayP("env", "e", nil, "environment variables (format: KEY=VALUE, can be repeated)")
	sandboxCmd.AddCommand(sandboxStartCmd)
}

// parseEnvFlags parses a slice of "KEY=VALUE" strings into a map.
func parseEnvFlags(envSlice []string) map[string]string {
	if len(envSlice) == 0 {
		return nil
	}
	envVars := make(map[string]string, len(envSlice))
	for _, e := range envSlice {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			envVars[parts[0]] = parts[1]
		}
	}
	return envVars
}

// sandboxStarter is a function that creates a Daytona client and creates a sandbox.
// Injected in tests to avoid real SDK calls.
type sandboxStarter func(ctx context.Context, apiKey, serverURL, name, snapshotID string, envVars map[string]string, out io.Writer) (*sandbox.CreateSandboxResult, error)

// defaultSandboxStarter creates a real Daytona client and calls CreateSandbox.
func defaultSandboxStarter(ctx context.Context, apiKey, serverURL, name, snapshotID string, envVars map[string]string, out io.Writer) (*sandbox.CreateSandboxResult, error) {
	client, err := sandbox.NewClient(apiKey, serverURL)
	if err != nil {
		return nil, fmt.Errorf("creating Daytona client: %w", err)
	}
	return sandbox.CreateSandbox(ctx, client, name, snapshotID, envVars, out)
}

// branchResolver is a function that returns the current git branch name.
// Injected in tests to avoid depending on actual git state.
type branchResolver func() (string, error)

// runSandboxStart contains the testable logic for the sandbox start command.
// dir is the project root directory (containing .hal/).
// If starter is nil, the real SDK client is used.
// If getBranch is nil, compound.CurrentBranch is used.
func runSandboxStart(dir, name string, envVars map[string]string, out io.Writer, starter sandboxStarter, getBranch branchResolver) error {
	return runSandboxStartWithDeps(dir, name, envVars, out, starter, getBranch, nil, nil)
}

// runSandboxStartWithDeps contains the testable logic for the sandbox start command.
// dir is the project root directory (containing .hal/).
// If starter is nil, the real SDK client is used.
// If getBranch is nil, compound.CurrentBranch is used.
// If lister or dockerfileCreator are nil, the real SDK client is used.
func runSandboxStartWithDeps(
	dir, name string,
	envVars map[string]string,
	out io.Writer,
	starter sandboxStarter,
	getBranch branchResolver,
	lister snapshotLister,
	dockerfileCreator snapshotFromDockerfileCreator,
) error {
	halDir := filepath.Join(dir, template.HalDir)
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return fmt.Errorf(".hal/ not found - run 'hal init' first")
	}

	// Load config and ensure auth
	cfg, err := compound.LoadDaytonaConfig(dir)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if err := sandbox.EnsureAuth(cfg.APIKey, func() error {
		return runSandboxAutoSetup(dir, out)
	}, func() (string, error) {
		reloaded, err := compound.LoadDaytonaConfig(dir)
		if err != nil {
			return "", err
		}
		return reloaded.APIKey, nil
	}); err != nil {
		return err
	}

	// Re-read config in case EnsureAuth triggered setup
	cfg, err = compound.LoadDaytonaConfig(dir)
	if err != nil {
		return fmt.Errorf("reloading config: %w", err)
	}

	name = strings.TrimSpace(name)
	if name == "" {
		if getBranch == nil {
			getBranch = compound.CurrentBranch
		}
		branch, err := getBranch()
		if err != nil {
			return fmt.Errorf("could not determine sandbox name from git branch: %w\n  use --name to specify a name", err)
		}
		name = sandbox.SandboxNameFromBranch(branch)
	}

	// Load sandbox env vars from config, then overlay any -e flag overrides
	sandboxCfg, _ := compound.LoadSandboxConfig(dir)
	mergedEnv := make(map[string]string)
	if sandboxCfg != nil {
		for k, v := range sandboxCfg.Env {
			mergedEnv[k] = v
		}
	}
	// -e flags override config values
	for k, v := range envVars {
		mergedEnv[k] = v
	}
	if len(mergedEnv) == 0 {
		mergedEnv = nil
	}

	snapshotID, err := resolveTemplateSnapshot(dir, cfg.APIKey, cfg.ServerURL, out, lister, dockerfileCreator)
	if err != nil {
		return fmt.Errorf("resolving template snapshot: %w", err)
	}

	envCount := len(mergedEnv)
	if envCount > 0 {
		fmt.Fprintf(out, "Starting sandbox %q from template snapshot %q (%s) with %d env vars...\n", name, sandboxTemplateSnapshotName, snapshotID, envCount)
	} else {
		fmt.Fprintf(out, "Starting sandbox %q from template snapshot %q (%s)...\n", name, sandboxTemplateSnapshotName, snapshotID)
	}

	if starter == nil {
		starter = defaultSandboxStarter
	}

	ctx := context.Background()
	result, err := starter(ctx, cfg.APIKey, cfg.ServerURL, name, snapshotID, mergedEnv, out)
	if err != nil {
		return fmt.Errorf("sandbox creation failed: %w", err)
	}

	// Save state
	state := &sandbox.SandboxState{
		Name:        result.Name,
		SnapshotID:  snapshotID,
		WorkspaceID: result.ID,
		Status:      result.Status,
		CreatedAt:   time.Now(),
	}
	if err := sandbox.SaveState(halDir, state); err != nil {
		return fmt.Errorf("saving sandbox state: %w", err)
	}

	fmt.Fprintf(out, "Sandbox started: %s (status: %s)\n", result.Name, result.Status)
	return nil
}
