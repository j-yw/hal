package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/spf13/cobra"
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
		return runSandboxStop(args, allFlag, pattern, os.Stdout, nil)
	},
}

func init() {
	sandboxCmd.AddCommand(sandboxStopCmd)
	sandboxStopCmd.Flags().Bool("all", false, "Stop all running sandboxes")
	sandboxStopCmd.Flags().String("pattern", "", "Stop sandboxes matching a glob pattern")
}

// sandboxStopListInstances is injectable for testing.
var sandboxStopListInstances = sandbox.ListInstances

// runSandboxStop is the public entry point for the stop command.
func runSandboxStop(args []string, allFlag bool, pattern string, out io.Writer, provider sandbox.Provider) error {
	return runSandboxStopWithDeps(args, allFlag, pattern, out, provider)
}

// runSandboxStopWithDeps contains the testable logic for the sandbox stop command.
// It resolves targets from the global registry, then stops each one.
func runSandboxStopWithDeps(args []string, allFlag bool, pattern string, out io.Writer, provider sandbox.Provider) error {
	targets, hint, err := resolveStopTargets(args, allFlag, pattern)
	if err != nil {
		return err
	}

	if hint != "" {
		fmt.Fprintln(out, hint)
	}

	// Stop each target (execution details in US-037; single-target path here)
	for _, target := range targets {
		if err := stopOneTarget(target, out, provider); err != nil {
			return err
		}
	}

	return nil
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

// resolveStopByNames loads each named sandbox from the registry.
func resolveStopByNames(names []string) ([]*sandbox.SandboxState, string, error) {
	seen := make(map[string]bool, len(names))
	targets := make([]*sandbox.SandboxState, 0, len(names))

	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true

		instance, err := sandbox.LoadInstance(name)
		if err != nil {
			return nil, "", fmt.Errorf("sandbox %q not found in registry", name)
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

// filterRunning returns only instances with Status == StatusRunning.
func filterRunning(instances []*sandbox.SandboxState) []*sandbox.SandboxState {
	result := make([]*sandbox.SandboxState, 0, len(instances))
	for _, inst := range instances {
		if inst.Status == sandbox.StatusRunning {
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

// stopOneTarget stops a single sandbox. If provider is nil, resolves from global config.
func stopOneTarget(target *sandbox.SandboxState, out io.Writer, provider sandbox.Provider) error {
	p := provider
	if p == nil {
		var err error
		p, err = resolveProviderFromGlobalConfig(target.Provider)
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

	fmt.Fprintf(out, "Sandbox %q stopped.\n", target.Name)
	return nil
}
