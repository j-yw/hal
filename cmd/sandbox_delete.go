package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	display "github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
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
		return runSandboxDelete(args, allFlag, yesFlag, pattern, cmd.InOrStdin(), cmd.OutOrStdout(), nil)
	},
}

func init() {
	sandboxCmd.AddCommand(sandboxDeleteCmd)
	sandboxDeleteCmd.Flags().Bool("all", false, "Delete all sandboxes")
	sandboxDeleteCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt for --all")
	sandboxDeleteCmd.Flags().String("pattern", "", "Delete sandboxes matching a glob pattern")
}

// sandboxDeleteListInstances is injectable for testing and resolves registry
// entries including staged removal fallbacks so interrupted deletes can be
// recovered through bulk selection paths.
var sandboxDeleteListInstances = sandbox.ListInstances

// sandboxDeleteLoadInstance is injectable for testing named target resolution.
var sandboxDeleteLoadInstance = sandbox.LoadInstance

type sandboxDeletePendingRemoval interface {
	Commit() error
	Rollback() error
	AlreadyStaged() bool
}

var sandboxDeleteStageInstanceRemoval = func(name string) (sandboxDeletePendingRemoval, error) {
	return sandbox.StageInstanceRemoval(name)
}

// runSandboxDelete is the public entry point for the delete command.
func runSandboxDelete(args []string, allFlag, yesFlag bool, pattern string, in io.Reader, out io.Writer, provider sandbox.Provider) error {
	return runSandboxDeleteWithDeps(args, allFlag, yesFlag, pattern, in, out, provider)
}

// runSandboxDeleteWithDeps contains the testable logic for the sandbox delete command.
// It resolves targets from the global registry, confirms when needed, then deletes each one.
func runSandboxDeleteWithDeps(args []string, allFlag, yesFlag bool, pattern string, in io.Reader, out io.Writer, provider sandbox.Provider) error {
	if err := runSandboxAutoMigrate(".", out); err != nil {
		return err
	}

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
		return deleteOneTarget(targets[0], ".", out, provider)
	}

	// Multiple targets: delete concurrently using errgroup
	return deleteMultipleTargets(targets, ".", out, provider)
}

// resolveDeleteTargets resolves which sandboxes to delete based on positional args,
// --all, and --pattern flags. Returns de-duplicated, name-sorted targets.
//
// Resolution rules:
//   - Explicit names: load each from registry
//   - --all: all sandboxes, including staged removal fallbacks
//   - --pattern: sandboxes matching the glob, including staged removal fallbacks
//   - No args/flags: auto-resolve from all deletable sandboxes, including staged removal fallbacks
func resolveDeleteTargets(args []string, allFlag bool, pattern string) ([]*sandbox.SandboxState, string, error) {
	if err := validateDeleteSelectors(args, allFlag, pattern); err != nil {
		return nil, "", err
	}

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

func validateDeleteSelectors(args []string, allFlag bool, pattern string) error {
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

// resolveDeleteAll returns all sandboxes from the registry, including staged
// removal fallbacks for interrupted delete recovery.
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
// Rules: 1 match → select + hint, 0 → error, >1 → error with choices.
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
func deleteOneTarget(target *sandbox.SandboxState, projectDir string, out io.Writer, provider sandbox.Provider) error {
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
	info := deleteConnectInfo(target)
	if err := validateDeleteConnectInfo(target, info); err != nil {
		return err
	}
	pendingRemoval, err := sandboxDeleteStageInstanceRemoval(target.Name)
	if err != nil {
		return fmt.Errorf("staging registry entry for %q: %w", target.Name, err)
	}
	if err := p.Delete(ctx, info, out); err != nil && !finalizeInterruptedDeleteRetry(target.Provider, pendingRemoval, err) {
		if rollbackErr := pendingRemoval.Rollback(); rollbackErr != nil {
			return fmt.Errorf("sandbox delete failed for %q: %w (registry rollback failed: %v)", target.Name, err, rollbackErr)
		}
		return fmt.Errorf("sandbox delete failed for %q: %w", target.Name, err)
	}

	halDir := filepath.Join(projectDir, template.HalDir)
	if err := removeMatchingLocalSandboxState(halDir, target); err != nil {
		fmt.Fprintf(out, "warning: failed to remove local sandbox state for %q: %v\n", target.Name, err)
	}

	if err := pendingRemoval.Commit(); err != nil {
		return fmt.Errorf("failed to finalize registry cleanup for %q: %w", target.Name, err)
	}

	fmt.Fprintf(out, "%s Deleted %s\n", display.StyleSuccess.Render("[OK]"), target.Name)
	return nil
}

// deleteMultipleTargets deletes multiple sandboxes concurrently using errgroup.
// Each target emits one result line; successful deletes are removed from the registry.
// Returns an error if any target fails.
func deleteMultipleTargets(targets []*sandbox.SandboxState, projectDir string, out io.Writer, provider sandbox.Provider) error {
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
					fmt.Fprintf(out, "%s Failed %s: %v\n", display.StyleError.Render("[!!]"), target.Name, err)
					results = append(results, deleteResult{Name: target.Name, Success: false, Err: err})
					mu.Unlock()
					return nil
				}
			}

			ctx := context.Background()
			info := deleteConnectInfo(target)
			err := validateDeleteConnectInfo(target, info)
			var pendingRemoval sandboxDeletePendingRemoval
			if err == nil {
				pendingRemoval, err = sandboxDeleteStageInstanceRemoval(target.Name)
			}
			if err == nil {
				err = p.Delete(ctx, info, io.Discard)
				if err != nil {
					if finalizeInterruptedDeleteRetry(target.Provider, pendingRemoval, err) {
						err = nil
					} else {
						if rollbackErr := pendingRemoval.Rollback(); rollbackErr != nil {
							err = fmt.Errorf("sandbox delete failed: %w (registry rollback failed: %v)", err, rollbackErr)
						} else {
							err = fmt.Errorf("sandbox delete failed: %w", err)
						}
					}
				}
			}
			var localCleanupErr error
			if err == nil {
				halDir := filepath.Join(projectDir, template.HalDir)
				localCleanupErr = removeMatchingLocalSandboxState(halDir, target)
				if commitErr := pendingRemoval.Commit(); commitErr != nil {
					err = fmt.Errorf("failed to finalize registry cleanup for %q: %w", target.Name, commitErr)
				}
			}

			mu.Lock()
			if err != nil {
				fmt.Fprintf(out, "%s Failed %s: %v\n", display.StyleError.Render("[!!]"), target.Name, err)
				results = append(results, deleteResult{Name: target.Name, Success: false, Err: err})
			} else {
				if localCleanupErr != nil {
					fmt.Fprintf(out, "warning: failed to remove local sandbox state for %q: %v\n", target.Name, localCleanupErr)
				}
				fmt.Fprintf(out, "%s Deleted %s\n", display.StyleSuccess.Render("[OK]"), target.Name)
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

func finalizeInterruptedDeleteRetry(provider string, pendingRemoval sandboxDeletePendingRemoval, err error) bool {
	if err == nil || pendingRemoval == nil {
		return false
	}
	if !pendingRemoval.AlreadyStaged() {
		return false
	}

	return isMissingSandboxDeleteError(provider, err)
}

func deleteConnectInfo(target *sandbox.SandboxState) *sandbox.ConnectInfo {
	info := sandbox.ConnectInfoFromState(target)
	if info == nil {
		info = &sandbox.ConnectInfo{}
	}
	if target == nil {
		return info
	}
	if strings.TrimSpace(info.Name) == "" {
		info.Name = strings.TrimSpace(target.Name)
	}
	return info
}

func validateDeleteConnectInfo(target *sandbox.SandboxState, info *sandbox.ConnectInfo) error {
	if target == nil {
		return nil
	}
	if target.Provider != "digitalocean" {
		return nil
	}
	if info == nil {
		return fmt.Errorf("sandbox %q is missing DigitalOcean droplet ID and name", target.Name)
	}
	if strings.TrimSpace(info.WorkspaceID) == "" && strings.TrimSpace(info.Name) == "" {
		return fmt.Errorf("sandbox %q is missing DigitalOcean droplet ID and name", target.Name)
	}
	return nil
}
