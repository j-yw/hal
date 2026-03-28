package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	display "github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

var sandboxStopCmd = &cobra.Command{
	Use:   "stop [NAME ...]",
	Short: "Stop one or more running sandboxes",
	Long: `Stop one or more running sandboxes.

Targets can be specified as positional arguments, with --all for every running
sandbox, or with --pattern to match a glob pattern.

When no arguments or flags are provided, the command auto-resolves:
  - If exactly one sandbox is running, it is selected automatically.
  - If zero running sandboxes exist, an error is returned.
  - If multiple are running, an error lists the available choices.

Resolved targets are de-duplicated and sorted by name before execution.`,
	Example: `  hal sandbox stop my-sandbox
  hal sandbox stop api-backend frontend
  hal sandbox stop --all
  hal sandbox stop --pattern "worker-*"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		allFlag, _ := cmd.Flags().GetBool("all")
		pattern, _ := cmd.Flags().GetString("pattern")
		return runSandboxStop(args, allFlag, pattern, cmd.OutOrStdout(), nil)
	},
}

func init() {
	sandboxCmd.AddCommand(sandboxStopCmd)
	sandboxStopCmd.Flags().Bool("all", false, "Stop all running sandboxes")
	sandboxStopCmd.Flags().String("pattern", "", "Stop sandboxes matching a glob pattern")
}

// sandboxStopListInstances is injectable for testing and resolves only active
// registry entries so staged delete backups are never treated as stop targets.
var sandboxStopListInstances = sandbox.ListActiveInstances

// sandboxStopLoadInstance is injectable for testing and resolves only active
// registry entries so explicit names do not revive staged delete backups.
var sandboxStopLoadInstance = sandbox.LoadActiveInstance

// sandboxStopNow is injectable for deterministic tests.
var sandboxStopNow = func() time.Time { return time.Now() }

// sandboxStopForceWrite is injectable for testing registry updates.
var sandboxStopForceWrite = sandbox.ForceWriteInstance

// runSandboxStop is the public entry point for the stop command.
func runSandboxStop(args []string, allFlag bool, pattern string, out io.Writer, provider sandbox.Provider) error {
	return runSandboxStopWithDeps(args, allFlag, pattern, out, provider)
}

// stopResult tracks the outcome of a single stop target.
type stopResult struct {
	Name    string
	Success bool
	Err     error
}

// runSandboxStopWithDeps contains the testable logic for the sandbox stop command.
// It resolves targets from the global registry, stops them concurrently,
// updates the registry for successful stops, and reports results.
func runSandboxStopWithDeps(args []string, allFlag bool, pattern string, out io.Writer, provider sandbox.Provider) error {
	if err := runSandboxAutoMigrate(".", out); err != nil {
		return err
	}

	targets, hint, err := resolveStopTargets(args, allFlag, pattern)
	if err != nil {
		return err
	}

	if hint != "" {
		fmt.Fprintln(out, hint)
	}

	// Single target: stop inline for simple output
	if len(targets) == 1 {
		return stopOneTarget(targets[0], out, provider)
	}

	// Multiple targets: stop concurrently using errgroup
	return stopMultipleTargets(targets, out, provider)
}

// resolveStopTargets resolves which sandboxes to stop based on positional args,
// --all, and --pattern flags. Returns de-duplicated, name-sorted targets.
//
// Resolution rules:
//   - Explicit names: load each from registry
//   - --all: all running sandboxes
//   - --pattern: running sandboxes matching the glob
//   - No args/flags: auto-resolve (1 running → select, 0 → error, >1 → error)
func resolveStopTargets(args []string, allFlag bool, pattern string) ([]*sandbox.SandboxState, string, error) {
	if err := validateStopSelectors(args, allFlag, pattern); err != nil {
		return nil, "", err
	}

	// Explicit names take precedence
	if len(args) > 0 {
		return resolveStopByNames(args)
	}

	// --all: all running sandboxes
	if allFlag {
		return resolveStopAll()
	}

	// --pattern: matching running sandboxes
	if pattern != "" {
		return resolveStopByPattern(pattern)
	}

	// No args, no flags: auto-resolve from running sandboxes
	return resolveStopAutoSelect()
}

func validateStopSelectors(args []string, allFlag bool, pattern string) error {
	selectors := 0
	if len(args) > 0 {
		selectors++
	}
	if allFlag {
		selectors++
	}
	if pattern != "" {
		selectors++
	}
	if selectors > 1 {
		return fmt.Errorf("sandbox names, --all, and --pattern are mutually exclusive")
	}
	return nil
}

// resolveStopByNames loads each named sandbox from the registry without
// rejecting explicit targets based on cached lifecycle status.
func resolveStopByNames(names []string) ([]*sandbox.SandboxState, string, error) {
	seen := make(map[string]bool, len(names))
	targets := make([]*sandbox.SandboxState, 0, len(names))

	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true

		instance, err := sandboxStopLoadInstance(name)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, "", fmt.Errorf("sandbox %q not found in registry", name)
			}
			return nil, "", fmt.Errorf("load sandbox %q from registry: %w", name, err)
		}
		targets = append(targets, instance)
	}

	sortTargetsByName(targets)
	return targets, "", nil
}

// resolveStopAll returns all running sandboxes from the registry.
func resolveStopAll() ([]*sandbox.SandboxState, string, error) {
	instances, err := sandboxStopListInstances()
	if err != nil {
		return nil, "", fmt.Errorf("listing sandboxes: %w", err)
	}

	targets := filterRunning(instances)
	if len(targets) == 0 {
		return nil, "", fmt.Errorf("no running sandboxes")
	}

	sortTargetsByName(targets)
	return targets, "", nil
}

// resolveStopByPattern returns running sandboxes whose names match the glob pattern.
func resolveStopByPattern(pattern string) ([]*sandbox.SandboxState, string, error) {
	// Validate pattern syntax before listing
	if _, err := filepath.Match(pattern, ""); err != nil {
		return nil, "", fmt.Errorf("invalid pattern %q: %w", pattern, err)
	}

	instances, err := sandboxStopListInstances()
	if err != nil {
		return nil, "", fmt.Errorf("listing sandboxes: %w", err)
	}

	targets := make([]*sandbox.SandboxState, 0)
	for _, inst := range filterRunning(instances) {
		matched, _ := filepath.Match(pattern, inst.Name)
		if matched {
			targets = append(targets, inst)
		}
	}

	if len(targets) == 0 {
		return nil, "", fmt.Errorf("no running sandboxes matching pattern %q", pattern)
	}

	sortTargetsByName(targets)
	return targets, "", nil
}

// resolveStopAutoSelect auto-resolves when no args or flags are provided.
// Rules: 1 running → select + hint, 0 running → error, >1 running → error with choices.
func resolveStopAutoSelect() ([]*sandbox.SandboxState, string, error) {
	instances, err := sandboxStopListInstances()
	if err != nil {
		return nil, "", fmt.Errorf("listing sandboxes: %w", err)
	}

	running := filterRunning(instances)

	switch len(running) {
	case 0:
		return nil, "", fmt.Errorf("no running sandboxes")
	case 1:
		hint := fmt.Sprintf("Stopping only running sandbox %q...", running[0].Name)
		return running, hint, nil
	default:
		names := make([]string, 0, len(running))
		for _, inst := range running {
			names = append(names, inst.Name)
		}
		sort.Strings(names)
		return nil, "", fmt.Errorf("multiple running sandboxes found: %s", joinNames(names))
	}
}

func isRunningStopTarget(inst *sandbox.SandboxState) bool {
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

// filterRunning returns only running instances.
func filterRunning(instances []*sandbox.SandboxState) []*sandbox.SandboxState {
	result := make([]*sandbox.SandboxState, 0, len(instances))
	for _, inst := range instances {
		if isRunningStopTarget(inst) {
			result = append(result, inst)
		}
	}
	return result
}

// sortTargetsByName sorts targets by Name in ascending order.
func sortTargetsByName(targets []*sandbox.SandboxState) {
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].Name < targets[j].Name
	})
}

// joinNames joins names with ", " for error messages.
func joinNames(names []string) string {
	result := ""
	for i, name := range names {
		if i > 0 {
			result += ", "
		}
		result += name
	}
	return result
}

// stopOneTarget stops a single sandbox, updates the registry, and reports the result.
// If provider is nil, resolves from global config.
func stopOneTarget(target *sandbox.SandboxState, out io.Writer, provider sandbox.Provider) error {
	p := provider
	if p == nil {
		var err error
		p, err = resolveProviderWithFallback(".", target.Provider)
		if err != nil {
			return fmt.Errorf("resolving provider for %q: %w", target.Name, err)
		}
	}

	fmt.Fprintf(out, "Stopping sandbox %q...\n", target.Name)

	ctx := context.Background()
	info := sandbox.ConnectInfoFromState(target)
	if err := p.Stop(ctx, info, out); err != nil {
		return fmt.Errorf("sandbox stop failed for %q: %w", target.Name, err)
	}

	if err := persistStoppedState(target); err != nil {
		return fmt.Errorf("persisting stopped state for %q: %w", target.Name, err)
	}
	if err := syncMatchingLocalSandboxState(filepath.Join(".", template.HalDir), target); err != nil {
		fmt.Fprintf(out, "warning: failed to sync local sandbox state for %q: %v\n", target.Name, err)
	}

	fmt.Fprintf(out, "%s Stopped %s\n", display.StyleSuccess.Render("[OK]"), target.Name)
	return nil
}

// stopMultipleTargets stops multiple sandboxes concurrently using errgroup.
// Each target emits one result line; successful stops update the registry.
// Returns an error if any target fails.
func stopMultipleTargets(targets []*sandbox.SandboxState, out io.Writer, provider sandbox.Provider) error {
	var (
		mu      sync.Mutex
		results = make([]stopResult, 0, len(targets))
	)

	g := new(errgroup.Group)

	for _, target := range targets {
		target := target // capture for goroutine
		g.Go(func() error {
			p := provider
			if p == nil {
				var err error
				p, err = resolveProviderWithFallback(".", target.Provider)
				if err != nil {
					mu.Lock()
					fmt.Fprintf(out, "%s Failed %s: %v\n", display.StyleError.Render("[!!]"), target.Name, err)
					results = append(results, stopResult{Name: target.Name, Success: false, Err: err})
					mu.Unlock()
					return nil
				}
			}

			ctx := context.Background()
			info := sandbox.ConnectInfoFromState(target)
			err := p.Stop(ctx, info, io.Discard)

			mu.Lock()
			if err != nil {
				fmt.Fprintf(out, "%s Failed %s: %v\n", display.StyleError.Render("[!!]"), target.Name, err)
				results = append(results, stopResult{Name: target.Name, Success: false, Err: err})
			} else {
				if regErr := persistStoppedState(target); regErr != nil {
					fmt.Fprintf(out, "%s Failed %s: persisting stopped state: %v\n", display.StyleError.Render("[!!]"), target.Name, regErr)
					results = append(results, stopResult{Name: target.Name, Success: false, Err: regErr})
				} else {
					if syncErr := syncMatchingLocalSandboxState(filepath.Join(".", template.HalDir), target); syncErr != nil {
						fmt.Fprintf(out, "warning: failed to sync local sandbox state for %q: %v\n", target.Name, syncErr)
					}
					fmt.Fprintf(out, "%s Stopped %s\n", display.StyleSuccess.Render("[OK]"), target.Name)
					results = append(results, stopResult{Name: target.Name, Success: true})
				}
			}
			mu.Unlock()

			return nil // don't propagate to errgroup; we track errors ourselves
		})
	}

	g.Wait()

	// Check for any failures
	var failed int
	for _, r := range results {
		if !r.Success {
			failed++
		}
	}

	if failed > 0 {
		return fmt.Errorf("%d/%d sandbox stops failed", failed, len(targets))
	}

	return nil
}

func persistStoppedState(target *sandbox.SandboxState) error {
	now := sandboxStopNow()
	target.Status = sandbox.StatusStopped
	target.StoppedAt = &now
	return sandboxStopForceWrite(target)
}

// updateStoppedState updates a sandbox's registry entry to stopped status.
func updateStoppedState(target *sandbox.SandboxState) error {
	if err := persistStoppedState(target); err != nil {
		return err
	}
	return syncMatchingLocalSandboxState(filepath.Join(".", template.HalDir), target)
}
