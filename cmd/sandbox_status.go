package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/spf13/cobra"
)

var sandboxStatusCmd = &cobra.Command{
	Use:   "status [NAME]",
	Short: "Show sandbox status",
	Long: `Show detailed status of a named sandbox, or list all sandboxes.

When a NAME is provided, queries the provider for live status and displays
all fields: identity, networking, lifecycle, config, and labels.

When no NAME is provided, delegates to 'hal sandbox list' to show all
sandboxes in the global registry.`,
	Example: `  hal sandbox status my-sandbox
  hal sandbox status`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return runSandboxList(os.Stdout, false, false)
		}
		return runSandboxStatus(args[0], os.Stdout, nil)
	},
}

func init() {
	sandboxCmd.AddCommand(sandboxStatusCmd)
}

// sandboxStatusLoadInstance is injectable for testing.
var sandboxStatusLoadInstance = sandbox.LoadInstance

// sandboxStatusResolveProvider is injectable for testing.
var sandboxStatusResolveProvider = resolveProviderFromGlobalConfig

// sandboxStatusNow is injectable for deterministic tests.
var sandboxStatusNow = func() time.Time { return time.Now() }

// runSandboxStatus is the public entry point for hal sandbox status NAME.
func runSandboxStatus(name string, out io.Writer, provider sandbox.Provider) error {
	return runSandboxStatusWithDeps(name, out, provider)
}

// runSandboxStatusWithDeps contains the testable logic for the sandbox status command.
// It loads the instance from the global registry, queries the provider for live status,
// and displays all SandboxState fields.
func runSandboxStatusWithDeps(name string, out io.Writer, provider sandbox.Provider) error {
	// Load instance from global registry
	instance, err := sandboxStatusLoadInstance(name)
	if err != nil {
		return fmt.Errorf("sandbox %q not found in registry", name)
	}

	// Resolve provider if not injected
	p := provider
	if p == nil {
		p, err = sandboxStatusResolveProvider(instance.Provider)
		if err != nil {
			return fmt.Errorf("resolving provider for %q: %w", instance.Name, err)
		}
	}

	// Query live status from provider
	info := sandbox.ConnectInfoFromState(instance)
	ctx, cancel := context.WithTimeout(context.Background(), liveStatusTimeout)
	defer cancel()

	liveErr := p.Status(ctx, info, io.Discard)
	if liveErr != nil {
		instance.Status = sandbox.StatusUnknown
	}

	// Display detailed info
	renderSandboxDetail(out, instance, liveErr)

	return nil
}

// renderSandboxDetail renders all SandboxState fields in a detailed view.
func renderSandboxDetail(out io.Writer, inst *sandbox.SandboxState, liveErr error) {
	now := sandboxStatusNow()

	fmt.Fprintf(out, "Name:       %s\n", inst.Name)
	fmt.Fprintf(out, "ID:         %s\n", inst.ID)
	fmt.Fprintf(out, "Provider:   %s\n", inst.Provider)
	fmt.Fprintf(out, "Status:     %s\n", inst.Status)

	if liveErr != nil {
		fmt.Fprintf(out, "Live query: failed (%s)\n", liveErr)
	} else {
		fmt.Fprintln(out, "Live query: ok")
	}

	fmt.Fprintln(out)

	// Networking
	fmt.Fprintln(out, "Networking:")
	if inst.IP != "" {
		fmt.Fprintf(out, "  Public IP:          %s\n", inst.IP)
	} else {
		fmt.Fprintln(out, "  Public IP:          —")
	}
	if inst.TailscaleIP != "" {
		fmt.Fprintf(out, "  Tailscale IP:       %s\n", inst.TailscaleIP)
	} else {
		fmt.Fprintln(out, "  Tailscale IP:       —")
	}
	if inst.TailscaleHostname != "" {
		fmt.Fprintf(out, "  Tailscale Hostname: %s\n", inst.TailscaleHostname)
	}
	preferredIP := sandbox.PreferredIP(inst)
	if preferredIP != "" {
		fmt.Fprintf(out, "  Active SSH IP:      %s\n", preferredIP)
	}

	if inst.WorkspaceID != "" {
		fmt.Fprintf(out, "  Workspace ID:       %s\n", inst.WorkspaceID)
	}

	fmt.Fprintln(out)

	// Lifecycle
	fmt.Fprintln(out, "Lifecycle:")
	fmt.Fprintf(out, "  Created:      %s (%s ago)\n", inst.CreatedAt.Format(time.RFC3339), formatAge(now.Sub(inst.CreatedAt)))
	if inst.StoppedAt != nil {
		fmt.Fprintf(out, "  Stopped:      %s (%s ago)\n", inst.StoppedAt.Format(time.RFC3339), formatAge(now.Sub(*inst.StoppedAt)))
	}

	fmt.Fprintln(out)

	// Config
	fmt.Fprintln(out, "Config:")
	if inst.AutoShutdown {
		fmt.Fprintf(out, "  Auto-shutdown: on (%dh idle)\n", inst.IdleHours)
	} else {
		fmt.Fprintln(out, "  Auto-shutdown: off")
	}
	if inst.Size != "" {
		fmt.Fprintf(out, "  Size:          %s\n", inst.Size)
	}

	// Cost
	cost := sandbox.EstimatedCost(inst, func() time.Time { return now })
	if cost >= 0 {
		fmt.Fprintf(out, "  Est. cost:     $%.2f\n", cost)
	}

	// Labels
	if inst.Repo != "" || inst.SnapshotID != "" {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Labels:")
		if inst.Repo != "" {
			fmt.Fprintf(out, "  Repo:       %s\n", inst.Repo)
		}
		if inst.SnapshotID != "" {
			fmt.Fprintf(out, "  Snapshot:   %s\n", inst.SnapshotID)
		}
	}
}
