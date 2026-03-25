package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/compound"
	display "github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

var sandboxStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Create and start a sandbox",
	Args:  noArgsValidation(),
	Long: `Create and start a sandbox using the configured provider (Daytona, Hetzner, DigitalOcean, or AWS Lightsail).

The sandbox name defaults to the current git branch (with slashes replaced by hyphens).
Use --name to override the default name.

Environment variables from .hal/config.yaml sandbox.env section are passed to the provider.
Additional -e/--env flags overlay config values.

Use --size to override the provider-specific instance size from config:
  - Hetzner: server type (e.g., cx22, cx42)
  - DigitalOcean: droplet size (e.g., s-2vcpu-4gb)
  - Lightsail: bundle ID (e.g., small_3_0, medium_3_0)

Use --repo to tag the sandbox with a repository label (informational only).

Use --force to replace an existing sandbox with the same name (deletes the old one first).

Auto-shutdown injects HAL_AUTO_SHUTDOWN and HAL_IDLE_HOURS env vars into the sandbox
so that cloud-init can configure idle timers. Defaults come from global sandbox config.`,
	Example: `  hal sandbox start
  hal sandbox start --name hal-dev
  hal sandbox start -n dev --size cx42
  hal sandbox start -n dev --force
  hal sandbox start -n dev --repo github.com/org/repo
  hal sandbox start -n dev -e TAILSCALE_AUTHKEY=tskey-auth-xxx -e ANTHROPIC_API_KEY=sk-ant-xxx
  hal sandbox start --no-auto-shutdown
  hal sandbox start --idle-hours 24
  hal sandbox start -n worker --count 5`,
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		count, _ := cmd.Flags().GetInt("count")
		force, _ := cmd.Flags().GetBool("force")
		size, _ := cmd.Flags().GetString("size")
		repo, _ := cmd.Flags().GetString("repo")
		envSlice, _ := cmd.Flags().GetStringArray("env")
		envVars := parseEnvFlags(envSlice)

		// Resolve auto-shutdown settings from flags
		opts := autoShutdownOpts{}
		if cmd.Flags().Changed("no-auto-shutdown") {
			v := true
			opts.noAutoShutdown = &v
		}
		if cmd.Flags().Changed("auto-shutdown") {
			v, _ := cmd.Flags().GetBool("auto-shutdown")
			opts.autoShutdown = &v
		}
		if cmd.Flags().Changed("idle-hours") {
			v, _ := cmd.Flags().GetInt("idle-hours")
			opts.idleHours = &v
		}

		return runSandboxStart(".", name, count, force, size, repo, envVars, opts, os.Stdout, nil)
	},
}

var resolveSandboxProvider = sandbox.ProviderFromConfig

func init() {
	sandboxStartCmd.Flags().StringP("name", "n", "", "sandbox name (defaults to current git branch)")
	sandboxStartCmd.Flags().Int("count", 0, "create N sandboxes with names {name}-01..{name}-N")
	sandboxStartCmd.Flags().BoolP("force", "f", false, "replace existing sandbox with the same name")
	sandboxStartCmd.Flags().StringP("size", "s", "", "override provider instance size (e.g., cx42, s-2vcpu-4gb)")
	sandboxStartCmd.Flags().StringP("repo", "r", "", "repository label for the sandbox (informational)")
	sandboxStartCmd.Flags().StringArrayP("env", "e", nil, "extra environment variables (KEY=VALUE, repeatable)")
	sandboxStartCmd.Flags().Bool("auto-shutdown", true, "enable auto-shutdown idle timer")
	sandboxStartCmd.Flags().Bool("no-auto-shutdown", false, "disable auto-shutdown idle timer")
	sandboxStartCmd.Flags().Int("idle-hours", 0, "hours before idle shutdown (default from global config)")
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

// autoShutdownOpts carries flag overrides for auto-shutdown configuration.
// Pointer fields distinguish "flag was set" from "flag was not set".
type autoShutdownOpts struct {
	autoShutdown   *bool // --auto-shutdown flag
	noAutoShutdown *bool // --no-auto-shutdown flag
	idleHours      *int  // --idle-hours flag
}

// sandboxStartDeps holds injectable dependencies for runSandboxStartWithDeps.
type sandboxStartDeps struct {
	provider  sandbox.Provider
	getBranch branchResolver
}

// resolveAutoShutdown merges global config defaults with flag overrides.
// --no-auto-shutdown takes precedence over --auto-shutdown.
func resolveAutoShutdown(globalCfg *sandbox.GlobalConfig, opts autoShutdownOpts) (autoShutdown bool, idleHours int) {
	// Start with global config defaults
	if globalCfg != nil {
		autoShutdown = globalCfg.Defaults.AutoShutdown
		idleHours = globalCfg.Defaults.IdleHours
	} else {
		// Fallback to hardcoded defaults matching DefaultGlobalConfig
		autoShutdown = true
		idleHours = 48
	}

	// Apply --auto-shutdown flag override
	if opts.autoShutdown != nil {
		autoShutdown = *opts.autoShutdown
	}

	// --no-auto-shutdown takes precedence
	if opts.noAutoShutdown != nil && *opts.noAutoShutdown {
		autoShutdown = false
	}

	// Apply --idle-hours flag override
	if opts.idleHours != nil {
		idleHours = *opts.idleHours
	}

	return autoShutdown, idleHours
}

// injectAutoShutdownEnv adds HAL_AUTO_SHUTDOWN and HAL_IDLE_HOURS env vars
// to the merged env map for cloud-init idle timer configuration.
func injectAutoShutdownEnv(env map[string]string, autoShutdown bool, idleHours int) {
	if autoShutdown {
		env["HAL_AUTO_SHUTDOWN"] = "true"
		env["HAL_IDLE_HOURS"] = fmt.Sprintf("%d", idleHours)
	} else {
		env["HAL_AUTO_SHUTDOWN"] = "false"
		// No HAL_IDLE_HOURS when auto-shutdown is disabled
		delete(env, "HAL_IDLE_HOURS")
	}
}

// runSandboxStart is the public entry point for sandbox start logic.
// It creates a sandboxStartDeps from the provided deps and delegates
// to runSandboxStartWithDeps.
func runSandboxStart(
	dir, name string,
	count int,
	force bool,
	size, repo string,
	envVars map[string]string,
	shutdownOpts autoShutdownOpts,
	out io.Writer,
	deps *sandboxStartDeps,
) error {
	var provider sandbox.Provider
	var getBranch branchResolver
	if deps != nil {
		provider = deps.provider
		getBranch = deps.getBranch
	}
	return runSandboxStartWithDeps(dir, name, count, force, size, repo, envVars, shutdownOpts, out, provider, getBranch)
}

// runSandboxStartWithDeps contains the testable logic for the sandbox start command.
// dir is the project root directory (containing .hal/).
// count specifies the number of sandboxes to create (0 or 1 = single sandbox).
// force replaces an existing sandbox with the same name (delete + recreate).
// size overrides the provider-specific instance size (e.g., cx42 for Hetzner).
// repo stores an informational repository label in SandboxState.
// If provider is nil, it is resolved from config via ProviderFromConfig.
// If getBranch is nil, compound.CurrentBranch is used.
func runSandboxStartWithDeps(
	dir, name string,
	count int,
	force bool,
	size, repo string,
	envVars map[string]string,
	shutdownOpts autoShutdownOpts,
	out io.Writer,
	provider sandbox.Provider,
	getBranch branchResolver,
) error {
	halDir := filepath.Join(dir, template.HalDir)
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return fmt.Errorf(".hal/ not found - run 'hal init' first")
	}

	if err := runSandboxAutoMigrate(dir, out); err != nil {
		return err
	}

	// Load sandbox config (provider, env, hetzner settings)
	sandboxCfg, err := compound.LoadSandboxConfig(dir)
	if err != nil {
		return fmt.Errorf("loading sandbox config: %w", err)
	}

	// Load global config for provider size defaults
	globalCfg, err := sandbox.LoadGlobalConfig()
	if err != nil {
		// Non-fatal: continue with local config alone
		globalCfg = nil
	}
	if globalCfg != nil {
		mergeGlobalSizeDefaults(sandboxCfg, globalCfg)
	}

	// Apply --size override to the active provider's size field
	size = strings.TrimSpace(size)
	if size != "" {
		applySizeOverride(sandboxCfg, size)
	}
	resolvedSize := configuredSandboxSize(sandboxCfg)

	// Resolve provider if not injected
	if provider == nil {
		dayCfg, err := compound.LoadDaytonaConfig(dir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		provCfg := sandbox.ProviderConfig{
			DaytonaAPIKey:             dayCfg.APIKey,
			DaytonaServerURL:          dayCfg.ServerURL,
			HetznerSSHKey:             sandboxCfg.Hetzner.SSHKey,
			HetznerServerType:         sandboxCfg.Hetzner.ServerType,
			HetznerImage:              sandboxCfg.Hetzner.Image,
			DigitalOceanSSHKey:        sandboxCfg.DigitalOcean.SSHKey,
			DigitalOceanSize:          sandboxCfg.DigitalOcean.Size,
			LightsailRegion:           sandboxCfg.Lightsail.Region,
			LightsailAvailabilityZone: sandboxCfg.Lightsail.AvailabilityZone,
			LightsailBundle:           sandboxCfg.Lightsail.Bundle,
			LightsailKeyPairName:      sandboxCfg.Lightsail.KeyPairName,
			TailscaleLockdown:         sandboxCfg.TailscaleLockdown,
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

	// Resolve auto-shutdown from global config + flag overrides
	autoShutdown, idleHours := resolveAutoShutdown(globalCfg, shutdownOpts)

	// Merge env vars: config values + CLI overrides
	mergedEnv := make(map[string]string)
	for k, v := range sandboxCfg.Env {
		mergedEnv[k] = v
	}
	for k, v := range envVars {
		mergedEnv[k] = v
	}

	// Inject auto-shutdown env vars for cloud-init
	injectAutoShutdownEnv(mergedEnv, autoShutdown, idleHours)

	if sandboxCfg.TailscaleLockdown {
		authKey := strings.TrimSpace(mergedEnv["TAILSCALE_AUTHKEY"])
		if authKey == "" {
			return fmt.Errorf("tailscale lockdown requires TAILSCALE_AUTHKEY (set sandbox.env.TAILSCALE_AUTHKEY or pass --env TAILSCALE_AUTHKEY=...)")
		}
	}

	// Batch mode: --count N creates multiple sandboxes
	if count > 1 {
		targets, err := batchPreflight(name, count)
		if err != nil {
			return err
		}
		return runBatchCreate(targets, provider, sandboxCfg, mergedEnv, autoShutdown, idleHours, resolvedSize, repo, halDir, out)
	}

	// Single sandbox creation
	return runSingleCreate(name, force, provider, sandboxCfg, mergedEnv, autoShutdown, idleHours, resolvedSize, repo, halDir, out)
}

// batchPreflight generates batch names and validates that none already exist
// in the global registry. Returns the list of target names on success.
func batchPreflight(base string, count int) ([]string, error) {
	targets, err := sandbox.BatchNames(base, count)
	if err != nil {
		return nil, fmt.Errorf("generating batch names: %w", err)
	}

	// Check each target name against the global registry
	var collisions []string
	for _, name := range targets {
		if _, err := sandbox.LoadInstance(name); err == nil {
			collisions = append(collisions, name)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("batch preflight failed: checking sandbox %q: %w", name, err)
		}
	}

	if len(collisions) > 0 {
		return nil, fmt.Errorf("batch preflight failed: sandboxes already exist: %s", strings.Join(collisions, ", "))
	}

	return targets, nil
}

// batchResult tracks the outcome of a single batch creation target.
type batchResult struct {
	Name    string
	Success bool
	Err     error
}

// runBatchCreate executes batch sandbox creation after preflight passes.
// provider.Create runs concurrently for all targets using errgroup.
// Only successful creations are persisted to the global registry.
// Returns an error when any target fails (exit code 1).
func runBatchCreate(
	targets []string,
	provider sandbox.Provider,
	sandboxCfg *compound.SandboxConfig,
	mergedEnv map[string]string,
	autoShutdown bool,
	idleHours int,
	size, repo string,
	halDir string,
	out io.Writer,
) error {
	fmt.Fprintf(out, "%s Creating %d sandboxes (%s)...\n", display.StyleInfo.Render("○"), len(targets), sandboxCfg.Provider)

	var (
		mu      sync.Mutex
		results = make([]batchResult, 0, len(targets))
	)

	g := new(errgroup.Group)

	for _, name := range targets {
		name := name // capture for goroutine
		g.Go(func() error {
			err := createBatchTarget(name, provider, sandboxCfg, mergedEnv, autoShutdown, idleHours, size, repo, out)

			mu.Lock()
			if err != nil {
				fmt.Fprintf(out, "%s Failed %s: %v\n", display.StyleError.Render("[!!]"), name, err)
				results = append(results, batchResult{Name: name, Success: false, Err: err})
			} else {
				fmt.Fprintf(out, "Created %s\n", name)
				results = append(results, batchResult{Name: name, Success: true})
			}
			mu.Unlock()

			return nil // don't propagate to errgroup; we track errors ourselves
		})
	}

	g.Wait()

	// Count successes and failures
	var success, failed int
	for _, r := range results {
		if r.Success {
			success++
		} else {
			failed++
		}
	}

	total := len(targets)
	fmt.Fprintf(out, "%d/%d created (%d failed). Failed sandboxes were not registered.\n", success, total, failed)

	if failed > 0 {
		return fmt.Errorf("%d/%d sandbox creations failed", failed, total)
	}

	return nil
}

// createBatchTarget creates a single sandbox in batch mode and persists it
// to the global registry on success. Provider output is prefixed with the
// sandbox name so concurrent goroutine output stays readable.
func createBatchTarget(
	name string,
	provider sandbox.Provider,
	sandboxCfg *compound.SandboxConfig,
	mergedEnv map[string]string,
	autoShutdown bool,
	idleHours int,
	size, repo string,
	out io.Writer,
) error {
	ctx := context.Background()
	// Always set a per-sandbox hostname so legacy static values are replaced.
	perEnv := make(map[string]string, len(mergedEnv)+1)
	for k, v := range mergedEnv {
		perEnv[k] = v
	}
	perEnv["TAILSCALE_HOSTNAME"] = name
	prefixedOut := &prefixWriter{prefix: "[" + name + "] ", w: out}
	result, err := provider.Create(ctx, name, perEnv, prefixedOut)
	if err != nil {
		return err
	}

	id, err := sandbox.NewV7()
	if err != nil {
		return fmt.Errorf("generating ID: %w", err)
	}

	state := &sandbox.SandboxState{
		ID:                id,
		Name:              name,
		Provider:          sandboxCfg.Provider,
		WorkspaceID:       result.ID,
		IP:                result.IP,
		TailscaleIP:       result.TailscaleIP,
		TailscaleHostname: sandbox.TailscaleHostname(name),
		Status:            sandbox.StatusRunning,
		CreatedAt:         time.Now(),
		AutoShutdown:      autoShutdown,
		IdleHours:         idleHours,
		Size:              size,
		Repo:              repo,
	}

	if err := sandbox.SaveInstance(state); err != nil {
		return fmt.Errorf("registering: %w", err)
	}

	return nil
}

// runSingleCreate creates one sandbox and persists it to the global registry.
// If force is true and a sandbox with the same name exists, it is deleted first.
func runSingleCreate(
	name string,
	force bool,
	provider sandbox.Provider,
	sandboxCfg *compound.SandboxConfig,
	mergedEnv map[string]string,
	autoShutdown bool,
	idleHours int,
	size, repo string,
	halDir string,
	out io.Writer,
) error {
	// Check for existing sandbox with the same name
	existing, loadErr := sandbox.LoadInstance(name)
	if loadErr == nil {
		// Sandbox exists
		if !force {
			return fmt.Errorf("sandbox %q already exists", name)
		}
		// --force: delete the existing sandbox before creating a new one
		fmt.Fprintf(out, "Replacing existing sandbox %q...\n", name)
		info := sandbox.ConnectInfoFromState(existing)
		ctx := context.Background()
		if err := provider.Delete(ctx, info, out); err != nil {
			return fmt.Errorf("force-delete of existing sandbox %q failed: %w", name, err)
		}
		if err := sandbox.RemoveInstance(name); err != nil {
			return fmt.Errorf("removing existing registry entry %q: %w", name, err)
		}
	} else if !errors.Is(loadErr, fs.ErrNotExist) {
		return fmt.Errorf("checking existing sandbox in registry: %w", loadErr)
	}

	envCount := len(mergedEnv)
	if envCount > 0 {
		fmt.Fprintf(out, "%s Starting sandbox %q (%s) with %d env vars...\n", display.StyleInfo.Render("○"), name, sandboxCfg.Provider, envCount)
	} else {
		fmt.Fprintf(out, "%s Starting sandbox %q (%s)...\n", display.StyleInfo.Render("○"), name, sandboxCfg.Provider)
	}

	// Always set a per-sandbox hostname so legacy static values are replaced.
	mergedEnv["TAILSCALE_HOSTNAME"] = name

	ctx := context.Background()
	result, err := provider.Create(ctx, name, mergedEnv, out)
	if err != nil {
		return fmt.Errorf("sandbox creation failed: %w", err)
	}

	// Generate UUIDv7 for the sandbox ID
	id, err := sandbox.NewV7()
	if err != nil {
		return fmt.Errorf("generating sandbox ID: %w", err)
	}

	// Build state with identity, provider, networking, lifecycle fields
	state := &sandbox.SandboxState{
		ID:                id,
		Name:              name,
		Provider:          sandboxCfg.Provider,
		WorkspaceID:       result.ID,
		IP:                result.IP,
		TailscaleIP:       result.TailscaleIP,
		TailscaleHostname: sandbox.TailscaleHostname(name),
		Status:            sandbox.StatusRunning,
		CreatedAt:         time.Now(),
		AutoShutdown:      autoShutdown,
		IdleHours:         idleHours,
		Size:              size,
		Repo:              repo,
	}

	// Persist to global registry
	if err := sandbox.SaveInstance(state); err != nil {
		return fmt.Errorf("registering sandbox: %w", err)
	}

	// Backward compat: also save to local .hal/sandbox.json
	if saveErr := sandbox.SaveState(halDir, state); saveErr != nil {
		fmt.Fprintf(out, "warning: could not save local state: %v\n", saveErr)
	}

	fmt.Fprintf(out, "%s Sandbox started: %s %s\n", display.StyleSuccess.Render("[OK]"), display.StyleBold.Render(name), display.StyleMuted.Render("(provider: "+sandboxCfg.Provider+")"))
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

// mergeGlobalSizeDefaults fills empty provider-specific size fields in
// localCfg with values from globalCfg. This ensures provider size defaults
// from global config apply when --size is not set.
func mergeGlobalSizeDefaults(localCfg *compound.SandboxConfig, globalCfg *sandbox.GlobalConfig) {
	// Hetzner
	if localCfg.Hetzner.ServerType == "" {
		localCfg.Hetzner.ServerType = globalCfg.Hetzner.ServerType
	}
	if localCfg.Hetzner.SSHKey == "" {
		localCfg.Hetzner.SSHKey = globalCfg.Hetzner.SSHKey
	}
	if localCfg.Hetzner.Image == "" {
		localCfg.Hetzner.Image = globalCfg.Hetzner.Image
	}
	// DigitalOcean
	if localCfg.DigitalOcean.Size == "" {
		localCfg.DigitalOcean.Size = globalCfg.DigitalOcean.Size
	}
	if localCfg.DigitalOcean.SSHKey == "" {
		localCfg.DigitalOcean.SSHKey = globalCfg.DigitalOcean.SSHKey
	}
	// Lightsail
	if localCfg.Lightsail.Bundle == "" {
		localCfg.Lightsail.Bundle = globalCfg.Lightsail.Bundle
	}
	if localCfg.Lightsail.Region == "" {
		localCfg.Lightsail.Region = globalCfg.Lightsail.Region
	}
	if localCfg.Lightsail.AvailabilityZone == "" {
		localCfg.Lightsail.AvailabilityZone = globalCfg.Lightsail.AvailabilityZone
	}
	if localCfg.Lightsail.KeyPairName == "" {
		localCfg.Lightsail.KeyPairName = globalCfg.Lightsail.KeyPairName
	}
}

// prefixWriter wraps a writer and prepends a prefix to each Write call.
// Used in batch mode so concurrent sandbox output stays identifiable.
type prefixWriter struct {
	prefix string
	w      io.Writer
	mu     sync.Mutex
}

func (pw *prefixWriter) Write(p []byte) (int, error) {
	pw.mu.Lock()
	defer pw.mu.Unlock()

	// Prepend prefix to each line for readability
	lines := strings.SplitAfter(string(p), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		if _, err := fmt.Fprintf(pw.w, "%s%s", pw.prefix, line); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// applySizeOverride sets the provider-specific size field from the --size flag.
// Hetzner uses ServerType, DigitalOcean uses Size, Lightsail uses Bundle.
func applySizeOverride(cfg *compound.SandboxConfig, size string) {
	switch cfg.Provider {
	case "hetzner":
		cfg.Hetzner.ServerType = size
	case "digitalocean":
		cfg.DigitalOcean.Size = size
	case "lightsail":
		cfg.Lightsail.Bundle = size
	}
}

// configuredSandboxSize returns the effective provider size after config/default merges and --size overrides.
func configuredSandboxSize(cfg *compound.SandboxConfig) string {
	switch cfg.Provider {
	case "hetzner":
		return strings.TrimSpace(cfg.Hetzner.ServerType)
	case "digitalocean":
		return strings.TrimSpace(cfg.DigitalOcean.Size)
	case "lightsail":
		return strings.TrimSpace(cfg.Lightsail.Bundle)
	default:
		return ""
	}
}
