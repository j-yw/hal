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

var sandboxStartCmd = &cobra.Command{
	Use:   "start [NAME ...]",
	Short: "Start stopped sandboxes",
	Long: `Start one or more stopped sandboxes.

Targets can be specified as positional arguments, with --all for every stopped
sandbox, or with --pattern to match a glob pattern.

When no arguments or flags are provided, the command auto-resolves:
  - If exactly one sandbox is stopped, it is selected automatically.
  - If zero stopped sandboxes exist, an error tells you to create one.
  - If multiple are stopped, an error lists the available choices.

Explicit names are loaded from the registry regardless of cached lifecycle
status, so stale registry state can be corrected by the provider's idempotent
start operation. Resolved targets are de-duplicated and sorted by name before
execution.`,
	Example: `  hal sandbox start my-sandbox
  hal sandbox start api-backend frontend
  hal sandbox start --all
  hal sandbox start --pattern "worker-*"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		allFlag, _ := cmd.Flags().GetBool("all")
		pattern, _ := cmd.Flags().GetString("pattern")
		return runSandboxStart(args, allFlag, pattern, cmd.OutOrStdout(), nil)
	},
}

func init() {
	sandboxCmd.AddCommand(sandboxStartCmd)
	sandboxStartCmd.Flags().Bool("all", false, "Start all stopped sandboxes")
	sandboxStartCmd.Flags().String("pattern", "", "Start sandboxes matching a glob pattern")
}

var sandboxStartListInstances = sandbox.ListActiveInstances
var sandboxStartLoadInstance = sandbox.LoadActiveInstance
var sandboxStartResolveProvider = func(providerName string) (sandbox.Provider, error) {
	return resolveProviderWithFallback(".", providerName)
}
var sandboxStartForceWrite = sandbox.ForceWriteInstance
var sandboxStartNow = func() time.Time { return time.Now() }

// runSandboxStart is the public entry point for the lifecycle start command.
func runSandboxStart(args []string, allFlag bool, pattern string, out io.Writer, provider sandbox.Provider) error {
	return runSandboxStartWithDeps(args, allFlag, pattern, out, provider)
}

type startResult struct {
	Name    string
	Success bool
	Err     error
}

func runSandboxStartWithDeps(args []string, allFlag bool, pattern string, out io.Writer, provider sandbox.Provider) error {
	if err := runSandboxAutoMigrate(".", out); err != nil {
		return err
	}

	targets, hint, err := resolveStartTargets(args, allFlag, pattern)
	if err != nil {
		return err
	}
	if hint != "" {
		fmt.Fprintln(out, hint)
	}

	if len(targets) == 1 {
		return startOneTarget(targets[0], out, provider)
	}
	return startMultipleTargets(targets, out, provider)
}

func resolveStartTargets(args []string, allFlag bool, pattern string) ([]*sandbox.SandboxState, string, error) {
	if err := validateStartSelectors(args, allFlag, pattern); err != nil {
		return nil, "", err
	}
	if len(args) > 0 {
		return resolveStartByNames(args)
	}
	if allFlag {
		return resolveStartAll()
	}
	if pattern != "" {
		return resolveStartByPattern(pattern)
	}
	return resolveStartAutoSelect()
}

func validateStartSelectors(args []string, allFlag bool, pattern string) error {
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

func resolveStartByNames(names []string) ([]*sandbox.SandboxState, string, error) {
	seen := make(map[string]bool, len(names))
	targets := make([]*sandbox.SandboxState, 0, len(names))
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		instance, err := sandboxStartLoadInstance(name)
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

func resolveStartAll() ([]*sandbox.SandboxState, string, error) {
	instances, err := sandboxStartListInstances()
	if err != nil {
		return nil, "", fmt.Errorf("listing sandboxes: %w", err)
	}
	targets := filterStopped(instances)
	if len(targets) == 0 {
		return nil, "", noStoppedSandboxesError()
	}
	sortTargetsByName(targets)
	return targets, "", nil
}

func resolveStartByPattern(pattern string) ([]*sandbox.SandboxState, string, error) {
	if _, err := filepath.Match(pattern, ""); err != nil {
		return nil, "", fmt.Errorf("invalid pattern %q: %w", pattern, err)
	}
	instances, err := sandboxStartListInstances()
	if err != nil {
		return nil, "", fmt.Errorf("listing sandboxes: %w", err)
	}
	targets := make([]*sandbox.SandboxState, 0)
	for _, inst := range filterStopped(instances) {
		matched, _ := filepath.Match(pattern, inst.Name)
		if matched {
			targets = append(targets, inst)
		}
	}
	if len(targets) == 0 {
		return nil, "", fmt.Errorf("no stopped sandboxes matching pattern %q; use 'hal sandbox create' to provision a new sandbox", pattern)
	}
	sortTargetsByName(targets)
	return targets, "", nil
}

func resolveStartAutoSelect() ([]*sandbox.SandboxState, string, error) {
	instances, err := sandboxStartListInstances()
	if err != nil {
		return nil, "", fmt.Errorf("listing sandboxes: %w", err)
	}
	stopped := filterStopped(instances)
	switch len(stopped) {
	case 0:
		return nil, "", noStoppedSandboxesError()
	case 1:
		return stopped, fmt.Sprintf("Starting only stopped sandbox %q...", stopped[0].Name), nil
	default:
		names := make([]string, 0, len(stopped))
		for _, inst := range stopped {
			names = append(names, inst.Name)
		}
		sort.Strings(names)
		return nil, "", fmt.Errorf("multiple stopped sandboxes found: %s", joinNames(names))
	}
}

func noStoppedSandboxesError() error {
	return fmt.Errorf("no stopped sandboxes; use 'hal sandbox create' to provision a new sandbox")
}

func isStoppedStartTarget(inst *sandbox.SandboxState) bool {
	return inst != nil && strings.TrimSpace(inst.Status) == sandbox.StatusStopped
}

func filterStopped(instances []*sandbox.SandboxState) []*sandbox.SandboxState {
	result := make([]*sandbox.SandboxState, 0, len(instances))
	for _, inst := range instances {
		if isStoppedStartTarget(inst) {
			result = append(result, inst)
		}
	}
	return result
}

func startOneTarget(target *sandbox.SandboxState, out io.Writer, provider sandbox.Provider) error {
	p := provider
	if p == nil {
		var err error
		p, err = sandboxStartResolveProvider(target.Provider)
		if err != nil {
			return fmt.Errorf("resolving provider for %q: %w", target.Name, err)
		}
	}

	fmt.Fprintf(out, "Starting sandbox %q...\n", target.Name)
	ctx := context.Background()
	info := sandbox.ConnectInfoFromState(target)
	result, err := p.Start(ctx, info, out)
	if err != nil {
		return fmt.Errorf("sandbox start failed for %q: %w", target.Name, err)
	}
	if err := persistStartedState(target, result); err != nil {
		if warning, ok := asLocalStateSyncWarning(err); ok {
			fmt.Fprintf(out, "warning: failed to sync local sandbox state for %q: %v\n", target.Name, warning.Unwrap())
		} else {
			return fmt.Errorf("persisting started state for %q: %w", target.Name, err)
		}
	}
	if err := refreshStartedLiveStatus(target, p); err != nil {
		if warning, ok := asLocalStateSyncWarning(err); ok {
			fmt.Fprintf(out, "warning: failed to sync local sandbox state for %q: %v\n", target.Name, warning.Unwrap())
		} else {
			fmt.Fprintf(out, "warning: live status lookup failed for %q: %v\n", target.Name, err)
		}
	}

	fmt.Fprintf(out, "%s Started %s\n", display.StyleSuccess.Render("[OK]"), target.Name)
	return nil
}

func startMultipleTargets(targets []*sandbox.SandboxState, out io.Writer, provider sandbox.Provider) error {
	var (
		mu      sync.Mutex
		results = make([]startResult, 0, len(targets))
	)
	g := new(errgroup.Group)
	for _, target := range targets {
		target := target
		g.Go(func() error {
			p := provider
			if p == nil {
				var err error
				p, err = sandboxStartResolveProvider(target.Provider)
				if err != nil {
					mu.Lock()
					fmt.Fprintf(out, "%s Failed %s: %v\n", display.StyleError.Render("[!!]"), target.Name, err)
					results = append(results, startResult{Name: target.Name, Success: false, Err: err})
					mu.Unlock()
					return nil
				}
			}

			ctx := context.Background()
			info := sandbox.ConnectInfoFromState(target)
			result, err := p.Start(ctx, info, io.Discard)

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				fmt.Fprintf(out, "%s Failed %s: %v\n", display.StyleError.Render("[!!]"), target.Name, err)
				results = append(results, startResult{Name: target.Name, Success: false, Err: err})
				return nil
			}
			if regErr := persistStartedState(target, result); regErr != nil {
				if warning, ok := asLocalStateSyncWarning(regErr); ok {
					fmt.Fprintf(out, "warning: failed to sync local sandbox state for %q: %v\n", target.Name, warning.Unwrap())
				} else {
					fmt.Fprintf(out, "%s Failed %s: persisting started state: %v\n", display.StyleError.Render("[!!]"), target.Name, regErr)
					results = append(results, startResult{Name: target.Name, Success: false, Err: regErr})
					return nil
				}
			}
			if liveErr := refreshStartedLiveStatus(target, p); liveErr != nil {
				if warning, ok := asLocalStateSyncWarning(liveErr); ok {
					fmt.Fprintf(out, "warning: failed to sync local sandbox state for %q: %v\n", target.Name, warning.Unwrap())
				} else {
					fmt.Fprintf(out, "warning: live status lookup failed for %q: %v\n", target.Name, liveErr)
				}
			}
			fmt.Fprintf(out, "%s Started %s\n", display.StyleSuccess.Render("[OK]"), target.Name)
			results = append(results, startResult{Name: target.Name, Success: true})
			return nil
		})
	}
	g.Wait()

	failed := 0
	for _, r := range results {
		if !r.Success {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d/%d sandbox starts failed", failed, len(targets))
	}
	return nil
}

func persistStartedState(target *sandbox.SandboxState, result *sandbox.LifecycleResult) error {
	if target == nil {
		return nil
	}
	target.Status = sandbox.StatusRunning
	target.StoppedAt = nil
	if result != nil {
		if ip := strings.TrimSpace(result.IP); ip != "" {
			target.IP = ip
		}
	}
	if err := sandboxStartForceWrite(target); err != nil {
		return err
	}
	if err := syncMatchingLocalSandboxState(filepath.Join(".", template.HalDir), target); err != nil {
		return &localStateSyncWarning{err: err}
	}
	return nil
}

func refreshStartedLiveStatus(target *sandbox.SandboxState, provider sandbox.Provider) error {
	if target == nil || provider == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), liveStatusTimeout)
	defer cancel()
	liveStatus, err := queryProviderLiveStatus(ctx, provider, sandbox.ConnectInfoFromState(target))
	if err != nil {
		if errors.Is(err, errLiveStatusUnparseable) {
			return nil
		}
		return err
	}
	writeTarget, err := liveStatusWriteTarget(target.Name, sandboxStartLoadInstance, sandboxStartForceWrite)
	if err != nil {
		return fmt.Errorf("load active sandbox %q: %w", target.Name, err)
	}
	return persistLiveStatusResult(target, liveStatus, sandboxStartNow(), writeTarget)
}
