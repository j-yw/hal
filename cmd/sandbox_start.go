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
	Long: `Create and start a sandbox using the configured provider (Daytona, Hetzner, or DigitalOcean).

The sandbox name defaults to the current git branch (with slashes replaced by hyphens).
Use --name to override the default name.

Environment variables from .hal/config.yaml sandbox.env section are passed to the provider.
Additional -e/--env flags overlay config values.`,
	Example: `  hal sandbox start
  hal sandbox start --name hal-dev
  hal sandbox start -n dev -e TAILSCALE_AUTHKEY=tskey-auth-xxx -e ANTHROPIC_API_KEY=sk-ant-xxx`,
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		envSlice, _ := cmd.Flags().GetStringArray("env")
		envVars := parseEnvFlags(envSlice)
		return runSandboxStartWithDeps(".", name, envVars, os.Stdout, nil, nil)
	},
}

var resolveSandboxProvider = sandbox.ProviderFromConfig

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

// branchResolver is a function that returns the current git branch name.
// Injected in tests to avoid depending on actual git state.
type branchResolver func() (string, error)

// startDeps holds injectable dependencies for runSandboxStartWithDeps.
type startDeps struct {
	provider  sandbox.Provider
	getBranch branchResolver
}

// runSandboxStartWithDeps contains the testable logic for the sandbox start command.
// dir is the project root directory (containing .hal/).
// If provider is nil, it is resolved from config via ProviderFromConfig.
// If getBranch is nil, compound.CurrentBranch is used.
func runSandboxStartWithDeps(
	dir, name string,
	envVars map[string]string,
	out io.Writer,
	provider sandbox.Provider,
	getBranch branchResolver,
) error {
	halDir := filepath.Join(dir, template.HalDir)
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return fmt.Errorf(".hal/ not found - run 'hal init' first")
	}

	// Load sandbox config (provider, env, hetzner settings)
	sandboxCfg, err := compound.LoadSandboxConfig(dir)
	if err != nil {
		return fmt.Errorf("loading sandbox config: %w", err)
	}

	// Resolve provider if not injected
	if provider == nil {
		dayCfg, err := compound.LoadDaytonaConfig(dir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		provCfg := sandbox.ProviderConfig{
			DaytonaAPIKey:            dayCfg.APIKey,
			DaytonaServerURL:         dayCfg.ServerURL,
			HetznerSSHKey:            sandboxCfg.Hetzner.SSHKey,
			HetznerServerType:        sandboxCfg.Hetzner.ServerType,
			HetznerImage:             sandboxCfg.Hetzner.Image,
			DigitalOceanSSHKey:       sandboxCfg.DigitalOcean.SSHKey,
			DigitalOceanSize:         sandboxCfg.DigitalOcean.Size,
			LightsailRegion:          sandboxCfg.Lightsail.Region,
			LightsailAvailabilityZone: sandboxCfg.Lightsail.AvailabilityZone,
			LightsailBundle:          sandboxCfg.Lightsail.Bundle,
			LightsailKeyPairName:     sandboxCfg.Lightsail.KeyPairName,
			TailscaleLockdown:        sandboxCfg.TailscaleLockdown,
			StateDir:                 halDir,
		}
		provider, err = resolveSandboxProvider(sandboxCfg.Provider, provCfg)
		if err != nil {
			return fmt.Errorf("resolving provider: %w", err)
		}
	}

	// Resolve sandbox name
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

	// Merge env vars: config values + CLI overrides
	mergedEnv := make(map[string]string)
	for k, v := range sandboxCfg.Env {
		mergedEnv[k] = v
	}
	for k, v := range envVars {
		mergedEnv[k] = v
	}
	if len(mergedEnv) == 0 {
		mergedEnv = nil
	}

	if sandboxCfg.TailscaleLockdown {
		authKey := strings.TrimSpace(mergedEnv["TAILSCALE_AUTHKEY"])
		if authKey == "" {
			return fmt.Errorf("tailscale lockdown requires TAILSCALE_AUTHKEY (set sandbox.env.TAILSCALE_AUTHKEY or pass --env TAILSCALE_AUTHKEY=...)")
		}
	}

	envCount := len(mergedEnv)
	if envCount > 0 {
		fmt.Fprintf(out, "Starting sandbox %q (%s) with %d env vars...\n", name, sandboxCfg.Provider, envCount)
	} else {
		fmt.Fprintf(out, "Starting sandbox %q (%s)...\n", name, sandboxCfg.Provider)
	}

	ctx := context.Background()
	result, err := provider.Create(ctx, name, mergedEnv, out)
	if err != nil {
		return fmt.Errorf("sandbox creation failed: %w", err)
	}

	// Save state with provider and IP
	state := &sandbox.SandboxState{
		Name:        result.Name,
		Provider:    sandboxCfg.Provider,
		IP:          result.IP,
		TailscaleIP: result.TailscaleIP,
		WorkspaceID: result.ID,
		CreatedAt:   time.Now(),
	}
	if err := sandbox.SaveState(halDir, state); err != nil {
		return fmt.Errorf("saving sandbox state: %w", err)
	}

	fmt.Fprintf(out, "Sandbox started: %s (provider: %s)\n", result.Name, sandboxCfg.Provider)
	if result.IP != "" {
		if sandboxCfg.TailscaleLockdown {
			fmt.Fprintf(out, "  Public IP:    %s (blocked -- Tailscale only)\n", result.IP)
		} else {
			fmt.Fprintf(out, "  Public IP:    %s\n", result.IP)
		}
	}
	if result.TailscaleIP != "" {
		fmt.Fprintf(out, "  Tailscale IP: %s\n", result.TailscaleIP)
		fmt.Fprintln(out, "  SSH:          hal sandbox ssh")
	}
	return nil
}
