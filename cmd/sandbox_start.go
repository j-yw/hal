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
		opts := autoShutdownOptsFromCommand(cmd)

		return runSandboxStart(".", name, count, force, size, repo, envVars, opts, os.Stdout, nil)
	},
}

var resolveSandboxProvider = sandbox.ProviderFromConfig
var sandboxStartResolveProviderForForceDelete = resolveProviderFromGlobalConfig
var newSandboxID = sandbox.NewV7

type sandboxStartPendingRemoval interface {
	Commit() error
	Rollback() error
	AlreadyStaged() bool
}

var sandboxStartStageInstanceRemoval = func(name string) (sandboxStartPendingRemoval, error) {
	return sandbox.StageInstanceRemoval(name)
}

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

func autoShutdownOptsFromCommand(cmd *cobra.Command) autoShutdownOpts {
	opts := autoShutdownOpts{}
	if cmd == nil {
		return opts
	}

	if cmd.Flags().Changed("no-auto-shutdown") {
		v, _ := cmd.Flags().GetBool("no-auto-shutdown")
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

	return opts
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

	// Load global sandbox config for runtime defaults.
	useGlobalConfig := false
	globalCfg, err := sandbox.LoadGlobalConfig()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			globalCfg = nil
		} else {
			return fmt.Errorf("loading global sandbox config: %w; fix %s or rerun 'hal sandbox setup'", err, sandbox.GlobalConfigPath())
		}
	} else if _, statErr := os.Stat(sandbox.GlobalConfigPath()); statErr == nil {
		useGlobalConfig = true
	}
	if globalCfg != nil {
		mergeGlobalStartDefaults(sandboxCfg, globalCfg, useGlobalConfig)
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

		daytonaAPIKey := dayCfg.APIKey
		daytonaServerURL := dayCfg.ServerURL
		if useGlobalConfig && globalCfg != nil {
			daytonaAPIKey = globalCfg.Daytona.APIKey
			daytonaServerURL = globalCfg.Daytona.ServerURL
		}

		provCfg := sandbox.ProviderConfig{
			DaytonaAPIKey:             daytonaAPIKey,
			DaytonaServerURL:          daytonaServerURL,
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
		targets, err := batchPreflightWithOptions(name, count, force, provider, sandboxCfg.Provider, out)
		if err != nil {
			return err
		}
		return runBatchCreate(targets, force, provider, sandboxCfg, mergedEnv, autoShutdown, idleHours, resolvedSize, repo, halDir, out)
	}

	// Single sandbox creation
	return runSingleCreate(name, force, provider, sandboxCfg, mergedEnv, autoShutdown, idleHours, resolvedSize, repo, halDir, out)
}

func batchPreflight(base string, count int) ([]string, error) {
	return batchPreflightWithOptions(base, count, false, nil, "", io.Discard)
}

// batchPreflightWithOptions generates batch names and validates global registry
// access for every target. When force is true, collisions are allowed here and
// handled later during per-target creation once the batch preflight succeeds.
func batchPreflightWithOptions(
	base string,
	count int,
	force bool,
	provider sandbox.Provider,
	activeProvider string,
	out io.Writer,
) ([]string, error) {
	targets, err := sandbox.BatchNames(base, count)
	if err != nil {
		return nil, fmt.Errorf("generating batch names: %w", err)
	}

	// Check each target name against the global registry
	var collisions []string
	for _, name := range targets {
		_, err := sandbox.LoadActiveInstance(name)
		if err == nil {
			if force {
				continue
			}
			collisions = append(collisions, name)
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("batch preflight failed: checking sandbox %q: %w", name, err)
		}

		if force {
			continue
		}

		_, err = sandbox.LoadInstance(name)
		if err == nil {
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

func cleanupCreatedSandbox(
	ctx context.Context,
	provider sandbox.Provider,
	providerName, name string,
	result *sandbox.SandboxResult,
	out io.Writer,
) error {
	info := &sandbox.ConnectInfo{Name: strings.TrimSpace(name)}
	if result != nil {
		info.WorkspaceID = strings.TrimSpace(result.ID)
		info.IP = strings.TrimSpace(result.TailscaleIP)
		if info.IP == "" {
			info.IP = strings.TrimSpace(result.IP)
		}
	}
	if strings.TrimSpace(providerName) == "digitalocean" && info.WorkspaceID == "" {
		return fmt.Errorf("cleanup created sandbox %q after registration failure: missing DigitalOcean droplet ID for rollback", name)
	}
	if err := provider.Delete(ctx, info, out); err != nil {
		return fmt.Errorf("cleanup created sandbox %q after registration failure: %w", name, err)
	}
	return nil
}

func ensureSandboxTargetAvailable(
	name string,
	force bool,
	provider sandbox.Provider,
	activeProvider string,
	out io.Writer,
) error {
	loadExisting := sandbox.LoadActiveInstance
	if force {
		loadExisting = sandbox.LoadInstance
	}

	existing, loadErr := loadExisting(name)
	if loadErr == nil {
		if !force {
			return fmt.Errorf("sandbox %q already exists", name)
		}
		return replaceExistingSandbox(existing, provider, activeProvider, out)
	}
	if !errors.Is(loadErr, fs.ErrNotExist) {
		return fmt.Errorf("checking existing sandbox in registry: %w", loadErr)
	}

	if force {
		return nil
	}

	if _, pendingErr := sandbox.LoadInstance(name); pendingErr == nil {
		return fmt.Errorf("sandbox %q has a pending removal; rerun with --force to resume cleanup before creating a replacement", name)
	} else if !errors.Is(pendingErr, fs.ErrNotExist) {
		return fmt.Errorf("checking pending sandbox removal in registry: %w", pendingErr)
	}

	return nil
}

func replaceExistingSandbox(
	existing *sandbox.SandboxState,
	provider sandbox.Provider,
	activeProvider string,
	out io.Writer,
) error {
	if existing == nil {
		return fmt.Errorf("existing sandbox state is required")
	}

	name := strings.TrimSpace(existing.Name)
	fmt.Fprintf(out, "Replacing existing sandbox %q...\n", name)

	deleteProvider := provider
	existingProvider := strings.TrimSpace(existing.Provider)
	activeProvider = strings.TrimSpace(activeProvider)
	if deleteProvider == nil || (existingProvider != "" && existingProvider != activeProvider) {
		providerName := existingProvider
		if providerName == "" {
			providerName = activeProvider
		}
		if providerName == "" {
			return fmt.Errorf("resolving provider for existing sandbox %q: provider is not set", name)
		}
		var err error
		deleteProvider, err = sandboxStartResolveProviderForForceDelete(providerName)
		if err != nil {
			return fmt.Errorf("resolving provider for existing sandbox %q: %w", name, err)
		}
	}

	info := sandbox.ConnectInfoFromState(existing)
	pendingRemoval, err := sandboxStartStageInstanceRemoval(name)
	if err != nil {
		return fmt.Errorf("staging existing registry entry %q: %w", name, err)
	}

	ctx := context.Background()
	providerForRetry := ""
	if existing != nil {
		providerForRetry = strings.TrimSpace(existing.Provider)
	}
	if err := deleteProvider.Delete(ctx, info, out); err != nil && !finalizeInterruptedStartReplaceRetry(providerForRetry, pendingRemoval, err) {
		if rollbackErr := pendingRemoval.Rollback(); rollbackErr != nil {
			return fmt.Errorf("force-delete of existing sandbox %q failed: %w (registry rollback failed: %v)", name, err, rollbackErr)
		}
		return fmt.Errorf("force-delete of existing sandbox %q failed: %w", name, err)
	}
	if err := removeMatchingLocalSandboxState(filepath.Join(".", template.HalDir), existing); err != nil {
		fmt.Fprintf(out, "warning: failed to remove local sandbox state for %q: %v\n", name, err)
	}
	if err := pendingRemoval.Commit(); err != nil {
		return fmt.Errorf("failed to finalize registry cleanup for %q: %w", name, err)
	}
	return nil
}

func finalizeInterruptedStartReplaceRetry(provider string, pendingRemoval sandboxStartPendingRemoval, err error) bool {
	if err == nil || pendingRemoval == nil || !pendingRemoval.AlreadyStaged() {
		return false
	}

	return isMissingSandboxDeleteError(provider, err)
}

// runBatchCreate executes batch sandbox creation after preflight passes.
// provider.Create runs concurrently for all targets using errgroup.
// Only successful creations are persisted to the global registry.
// Returns an error when any target fails (exit code 1).
func runBatchCreate(
	targets []string,
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
	fmt.Fprintf(out, "%s Creating %d sandboxes (%s)...\n", display.StyleInfo.Render("○"), len(targets), sandboxCfg.Provider)

	var (
		mu      sync.Mutex
		results = make([]batchResult, 0, len(targets))
	)

	g := new(errgroup.Group)

	for _, name := range targets {
		name := name // capture for goroutine
		g.Go(func() error {
			err := createBatchTarget(name, force, provider, sandboxCfg, mergedEnv, autoShutdown, idleHours, size, repo, out)

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
	force bool,
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
	perEnv["TAILSCALE_HOSTNAME"] = sandbox.TailscaleHostname(name)
	prefixedOut := &prefixWriter{prefix: "[" + name + "] ", w: out}
	if err := ensureSandboxTargetAvailable(name, force, provider, sandboxCfg.Provider, prefixedOut); err != nil {
		return err
	}
	result, err := provider.Create(ctx, name, perEnv, prefixedOut)
	if err != nil {
		return err
	}

	id, err := newSandboxID()
	if err != nil {
		if cleanupErr := cleanupCreatedSandbox(ctx, provider, sandboxCfg.Provider, name, result, prefixedOut); cleanupErr != nil {
			return fmt.Errorf("generating ID: %w; %v", err, cleanupErr)
		}
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
		if cleanupErr := cleanupCreatedSandbox(ctx, provider, sandboxCfg.Provider, name, result, prefixedOut); cleanupErr != nil {
			return fmt.Errorf("registering: %w; %v", err, cleanupErr)
		}
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
	if err := ensureSandboxTargetAvailable(name, force, provider, sandboxCfg.Provider, out); err != nil {
		return err
	}

	envCount := len(mergedEnv)
	if envCount > 0 {
		fmt.Fprintf(out, "%s Starting sandbox %q (%s) with %d env vars...\n", display.StyleInfo.Render("○"), name, sandboxCfg.Provider, envCount)
	} else {
		fmt.Fprintf(out, "%s Starting sandbox %q (%s)...\n", display.StyleInfo.Render("○"), name, sandboxCfg.Provider)
	}

	// Always set a per-sandbox hostname so legacy static values are replaced.
	mergedEnv["TAILSCALE_HOSTNAME"] = sandbox.TailscaleHostname(name)

	ctx := context.Background()
	result, err := provider.Create(ctx, name, mergedEnv, out)
	if err != nil {
		return fmt.Errorf("sandbox creation failed: %w", err)
	}

	// Generate UUIDv7 for the sandbox ID
	id, err := newSandboxID()
	if err != nil {
		if cleanupErr := cleanupCreatedSandbox(ctx, provider, sandboxCfg.Provider, name, result, out); cleanupErr != nil {
			return fmt.Errorf("generating sandbox ID: %w; %v", err, cleanupErr)
		}
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
		if cleanupErr := cleanupCreatedSandbox(ctx, provider, sandboxCfg.Provider, name, result, out); cleanupErr != nil {
			return fmt.Errorf("registering sandbox: %w; %v", err, cleanupErr)
		}
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

// mergeGlobalStartDefaults overlays globally configured runtime settings onto
// the local sandbox config used by `hal sandbox start`. When a real global
// config file exists, it is authoritative for runtime settings and provider
// credentials; project-local copies remain only as a fallback when there is no
// global sandbox config yet.
func mergeGlobalStartDefaults(localCfg *compound.SandboxConfig, globalCfg *sandbox.GlobalConfig, useGlobalConfig bool) {
	if localCfg == nil || globalCfg == nil {
		return
	}

	if useGlobalConfig {
		if provider := strings.TrimSpace(globalCfg.Provider); provider != "" {
			localCfg.Provider = provider
		}
		if len(globalCfg.Env) > 0 {
			authoritativeEnv := make(map[string]string, len(globalCfg.Env))
			for k, v := range globalCfg.Env {
				authoritativeEnv[k] = v
			}
			localCfg.Env = authoritativeEnv
		} else {
			localCfg.Env = nil
		}
		localCfg.TailscaleLockdown = globalCfg.TailscaleLockdown
		localCfg.Hetzner = compound.HetznerConfig{
			ServerType: globalCfg.Hetzner.ServerType,
			SSHKey:     globalCfg.Hetzner.SSHKey,
			Image:      globalCfg.Hetzner.Image,
		}
		localCfg.DigitalOcean = compound.DigitalOceanConfig{
			Size:   globalCfg.DigitalOcean.Size,
			SSHKey: globalCfg.DigitalOcean.SSHKey,
		}
		localCfg.Lightsail = compound.LightsailConfig{
			Bundle:           globalCfg.Lightsail.Bundle,
			Region:           globalCfg.Lightsail.Region,
			AvailabilityZone: globalCfg.Lightsail.AvailabilityZone,
			KeyPairName:      globalCfg.Lightsail.KeyPairName,
		}
		return
	}

	if strings.TrimSpace(localCfg.Hetzner.ServerType) == "" && strings.TrimSpace(globalCfg.Hetzner.ServerType) != "" {
		localCfg.Hetzner.ServerType = globalCfg.Hetzner.ServerType
	}
	if strings.TrimSpace(localCfg.Hetzner.SSHKey) == "" && strings.TrimSpace(globalCfg.Hetzner.SSHKey) != "" {
		localCfg.Hetzner.SSHKey = globalCfg.Hetzner.SSHKey
	}
	if strings.TrimSpace(localCfg.Hetzner.Image) == "" && strings.TrimSpace(globalCfg.Hetzner.Image) != "" {
		localCfg.Hetzner.Image = globalCfg.Hetzner.Image
	}

	if strings.TrimSpace(localCfg.DigitalOcean.Size) == "" && strings.TrimSpace(globalCfg.DigitalOcean.Size) != "" {
		localCfg.DigitalOcean.Size = globalCfg.DigitalOcean.Size
	}
	if strings.TrimSpace(localCfg.DigitalOcean.SSHKey) == "" && strings.TrimSpace(globalCfg.DigitalOcean.SSHKey) != "" {
		localCfg.DigitalOcean.SSHKey = globalCfg.DigitalOcean.SSHKey
	}

	if strings.TrimSpace(localCfg.Lightsail.Bundle) == "" && strings.TrimSpace(globalCfg.Lightsail.Bundle) != "" {
		localCfg.Lightsail.Bundle = globalCfg.Lightsail.Bundle
	}
	if strings.TrimSpace(localCfg.Lightsail.Region) == "" && strings.TrimSpace(globalCfg.Lightsail.Region) != "" {
		localCfg.Lightsail.Region = globalCfg.Lightsail.Region
	}
	if strings.TrimSpace(localCfg.Lightsail.AvailabilityZone) == "" && strings.TrimSpace(globalCfg.Lightsail.AvailabilityZone) != "" {
		localCfg.Lightsail.AvailabilityZone = globalCfg.Lightsail.AvailabilityZone
	}
	if strings.TrimSpace(localCfg.Lightsail.KeyPairName) == "" && strings.TrimSpace(globalCfg.Lightsail.KeyPairName) != "" {
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
