package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	display "github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

var sandboxDeleteCmd = &cobra.Command{
	Use:   "delete [NAME ...]",
	Short: "Delete one or more sandboxes permanently",
	Long: `Permanently delete one or more sandboxes.

Targets can be specified as positional arguments, with --all for every sandbox,
or with --pattern to match a glob pattern.

When no arguments or flags are provided, the command auto-resolves:
  - If exactly one sandbox exists, it is selected automatically.
  - If zero sandboxes exist, an error is returned.
  - If multiple exist, an error lists the available choices.

When --all is used without --yes, a confirmation prompt is shown.

Resolved targets are de-duplicated and sorted by name before execution.`,
	Example: `  hal sandbox delete my-sandbox
  hal sandbox delete api-backend frontend
  hal sandbox delete --all --yes
  hal sandbox delete --pattern "worker-*"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		allFlag, _ := cmd.Flags().GetBool("all")
		yesFlag, _ := cmd.Flags().GetBool("yes")
		pattern, _ := cmd.Flags().GetString("pattern")
		return runSandboxDelete(args, allFlag, yesFlag, pattern, os.Stdin, os.Stdout, nil)
	},
}

func init() {
	sandboxCmd.AddCommand(sandboxDeleteCmd)
	sandboxDeleteCmd.Flags().Bool("all", false, "Delete all sandboxes")
	sandboxDeleteCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt for --all")
	sandboxDeleteCmd.Flags().String("pattern", "", "Delete sandboxes matching a glob pattern")
}

// sandboxDeleteListInstances is injectable for testing.
var sandboxDeleteListInstances = sandbox.ListInstances

// sandboxDeleteLoadInstance is injectable for testing named target resolution.
var sandboxDeleteLoadInstance = sandbox.LoadInstance

// sandboxDeleteRemoveInstance is injectable for testing registry removal.
var sandboxDeleteRemoveInstance = sandbox.RemoveInstance

// runSandboxDelete is the public entry point for the delete command.
func runSandboxDelete(args []string, allFlag, yesFlag bool, pattern string, in io.Reader, out io.Writer, provider sandbox.Provider) error {
	return runSandboxDeleteWithDeps(args, allFlag, yesFlag, pattern, in, out, provider)
}

// runSandboxDeleteWithDeps contains the testable logic for the sandbox delete command.
// It resolves targets from the global registry, confirms when needed, then deletes each one.
func runSandboxDeleteWithDeps(args []string, allFlag, yesFlag bool, pattern string, in io.Reader, out io.Writer, provider sandbox.Provider) error {
	targets, hint, err := resolveDeleteTargets(args, allFlag, pattern)
	if err != nil {
		return err
	}

	if hint != "" {
		fmt.Fprintln(out, hint)
	}

	// Confirmation prompt for --all without --yes
	if allFlag && !yesFlag {
		if !confirmDeleteAll(in, out) {
			fmt.Fprintln(out, "Aborted.")
			return nil
		}
	}

	// Single target: delete inline for simple output
	if len(targets) == 1 {
		return deleteOneTarget(targets[0], out, provider)
	}

	// Multiple targets: delete concurrently using errgroup
	return deleteMultipleTargets(targets, out, provider)
}

// resolveDeleteTargets resolves which sandboxes to delete based on positional args,
// --all, and --pattern flags. Returns de-duplicated, name-sorted targets.
//
// Resolution rules:
//   - Explicit names: load each from registry
//   - --all: all sandboxes
//   - --pattern: sandboxes matching the glob
//   - No args/flags: auto-resolve (1 → select, 0 → error, >1 → error)
func resolveDeleteTargets(args []string, allFlag bool, pattern string) ([]*sandbox.SandboxState, string, error) {
	// Explicit names take precedence
	if len(args) > 0 {
		return resolveDeleteByNames(args)
	}

	// --all: all sandboxes
	if allFlag {
		return resolveDeleteAll()
	}

	// --pattern: matching sandboxes
	if pattern != "" {
		return resolveDeleteByPattern(pattern)
	}

	// No args, no flags: auto-resolve from all sandboxes
	return resolveDeleteAutoSelect()
}

// resolveDeleteByNames loads each named sandbox from the registry.
func resolveDeleteByNames(names []string) ([]*sandbox.SandboxState, string, error) {
	seen := make(map[string]bool, len(names))
	targets := make([]*sandbox.SandboxState, 0, len(names))

	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true

		instance, err := sandboxDeleteLoadInstance(name)
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

// resolveDeleteAll returns all sandboxes from the registry.
func resolveDeleteAll() ([]*sandbox.SandboxState, string, error) {
	instances, err := sandboxDeleteListInstances()
	if err != nil {
		return nil, "", fmt.Errorf("listing sandboxes: %w", err)
	}

	if len(instances) == 0 {
		return nil, "", fmt.Errorf("no sandboxes found")
	}

	sortTargetsByName(instances)
	return instances, "", nil
}

// resolveDeleteByPattern returns sandboxes whose names match the glob pattern.
func resolveDeleteByPattern(pattern string) ([]*sandbox.SandboxState, string, error) {
	// Validate pattern syntax before listing
	if _, err := filepath.Match(pattern, ""); err != nil {
		return nil, "", fmt.Errorf("invalid pattern %q: %w", pattern, err)
	}

	instances, err := sandboxDeleteListInstances()
	if err != nil {
		return nil, "", fmt.Errorf("listing sandboxes: %w", err)
	}

	targets := make([]*sandbox.SandboxState, 0)
	for _, inst := range instances {
		matched, _ := filepath.Match(pattern, inst.Name)
		if matched {
			targets = append(targets, inst)
		}
	}

	if len(targets) == 0 {
		return nil, "", fmt.Errorf("no sandboxes matching pattern %q", pattern)
	}

	sortTargetsByName(targets)
	return targets, "", nil
}

// resolveDeleteAutoSelect auto-resolves when no args or flags are provided.
// Rules: 1 → select + hint, 0 → error, >1 → error with choices.
func resolveDeleteAutoSelect() ([]*sandbox.SandboxState, string, error) {
	instances, err := sandboxDeleteListInstances()
	if err != nil {
		return nil, "", fmt.Errorf("listing sandboxes: %w", err)
	}

	switch len(instances) {
	case 0:
		return nil, "", fmt.Errorf("no sandboxes found")
	case 1:
		hint := fmt.Sprintf("Deleting only sandbox %q...", instances[0].Name)
		return instances, hint, nil
	default:
		names := make([]string, 0, len(instances))
		for _, inst := range instances {
			names = append(names, inst.Name)
		}
		sort.Strings(names)
		return nil, "", fmt.Errorf("multiple sandboxes found: %s", joinNames(names))
	}
}

// confirmDeleteAll prompts the user for confirmation when --all is used without --yes.
// Returns true if user confirms.
func confirmDeleteAll(in io.Reader, out io.Writer) bool {
	fmt.Fprint(out, "Delete all sandboxes? [y/N] ")
	scanner := bufio.NewScanner(in)
	if !scanner.Scan() {
		return false
	}
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
	return answer == "y" || answer == "yes"
}

// deleteResult tracks the outcome of a single delete target.
type deleteResult struct {
	Name    string
	Success bool
	Err     error
}

// deleteOneTarget deletes a single sandbox, removes it from the registry, and reports the result.
// If provider is nil, resolves from global config.
func deleteOneTarget(target *sandbox.SandboxState, out io.Writer, provider sandbox.Provider) error {
	p := provider
	if p == nil {
		var err error
		p, err = resolveProviderFromGlobalConfig(target.Provider)
		if err != nil {
			return fmt.Errorf("resolving provider for %q: %w", target.Name, err)
		}
	}

	fmt.Fprintf(out, "Deleting sandbox %q...\n", target.Name)

	ctx := context.Background()
	info := sandbox.ConnectInfoFromState(target)
	if err := p.Delete(ctx, info, out); err != nil {
		return fmt.Errorf("sandbox delete failed for %q: %w", target.Name, err)
	}

	// Remove from global registry after successful provider delete
	if err := sandboxDeleteRemoveInstance(target.Name); err != nil {
		fmt.Fprintf(out, "warning: failed to remove registry entry for %q: %v\n", target.Name, err)
	}

	fmt.Fprintf(out, "%s Deleted %s\n", display.StyleSuccess.Render("[OK]"), target.Name)
	return nil
}

// deleteMultipleTargets deletes multiple sandboxes concurrently using errgroup.
// Each target emits one result line; successful deletes are removed from the registry.
// Returns an error if any target fails.
func deleteMultipleTargets(targets []*sandbox.SandboxState, out io.Writer, provider sandbox.Provider) error {
	var (
		mu      sync.Mutex
		results = make([]deleteResult, 0, len(targets))
	)

	g := new(errgroup.Group)

	for _, target := range targets {
		target := target // capture for goroutine
		g.Go(func() error {
			p := provider
			if p == nil {
				var err error
				p, err = resolveProviderFromGlobalConfig(target.Provider)
				if err != nil {
					mu.Lock()
					fmt.Fprintf(out, "Failed %s: %v\n", target.Name, err)
					results = append(results, deleteResult{Name: target.Name, Success: false, Err: err})
					mu.Unlock()
					return nil
				}
			}

			ctx := context.Background()
			info := sandbox.ConnectInfoFromState(target)
			err := p.Delete(ctx, info, io.Discard)

			mu.Lock()
			if err != nil {
				fmt.Fprintf(out, "Failed %s: %v\n", target.Name, err)
				results = append(results, deleteResult{Name: target.Name, Success: false, Err: err})
			} else {
				// Remove from global registry after successful provider delete
				if regErr := sandboxDeleteRemoveInstance(target.Name); regErr != nil {
					fmt.Fprintf(out, "Deleted %s (warning: registry removal failed: %v)\n", target.Name, regErr)
				} else {
					fmt.Fprintf(out, "%s Deleted %s\n", display.StyleSuccess.Render("[OK]"), target.Name)
				}
				results = append(results, deleteResult{Name: target.Name, Success: true})
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
		return fmt.Errorf("%d/%d sandbox deletes failed", failed, len(targets))
	}

	return nil
}
