package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	display "github.com/jywlabs/hal/internal/engine"
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
		out := io.Writer(os.Stdout)
		errOut := io.Writer(os.Stderr)
		if cmd != nil {
			out = cmd.OutOrStdout()
			errOut = cmd.ErrOrStderr()
		}
		if len(args) == 0 {
			return runSandboxListWithWriters(out, errOut, false, false)
		}
		return runSandboxStatus(args[0], out, nil)
	},
}

func init() {
	sandboxCmd.AddCommand(sandboxStatusCmd)
}

// sandboxStatusLoadInstance is injectable for testing.
var sandboxStatusLoadInstance = sandbox.LoadInstance

// sandboxStatusResolveProvider is injectable for testing.
var sandboxStatusResolveProvider = resolveProviderFromGlobalConfig

// sandboxStatusLoadActiveInstance checks whether a sandbox still has an active
// registry entry before a live refresh persists updates.
var sandboxStatusLoadActiveInstance = sandbox.LoadActiveInstance

// sandboxStatusForceWrite persists successful live status refreshes.
var sandboxStatusForceWrite = sandbox.ForceWriteInstance

// sandboxStatusNow is injectable for deterministic tests.
var sandboxStatusNow = func() time.Time { return time.Now() }

func liveStatusWriteTarget(
	name string,
	loadActive func(string) (*sandbox.SandboxState, error),
	write func(*sandbox.SandboxState) error,
) (func(*sandbox.SandboxState) error, error) {
	if write == nil || loadActive == nil {
		return write, nil
	}

	if _, err := loadActive(name); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	return func(updated *sandbox.SandboxState) error {
		current, err := loadActive(name)
		if err != nil {
			return err
		}
		if current == nil {
			return fs.ErrNotExist
		}

		current.Status = updated.Status
		current.StoppedAt = cloneStoppedAt(updated.StoppedAt)
		if ip := strings.TrimSpace(updated.IP); ip != "" {
			current.IP = ip
		}
		return write(current)
	}, nil
}

// runSandboxStatus is the public entry point for hal sandbox status NAME.
func runSandboxStatus(name string, out io.Writer, provider sandbox.Provider) error {
	return runSandboxStatusWithDeps(name, out, provider)
}

// runSandboxStatusWithDeps contains the testable logic for the sandbox status command.
// It loads the instance from the global registry, queries the provider for live status,
// and displays all SandboxState fields.
func runSandboxStatusWithDeps(name string, out io.Writer, provider sandbox.Provider) error {
	if err := runSandboxAutoMigrate(".", out); err != nil {
		return err
	}

	// Load instance from global registry
	instance, err := sandboxStatusLoadInstance(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("sandbox %q not found in registry", name)
		}
		return fmt.Errorf("load sandbox %q from registry: %w", name, err)
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

	liveStatus, liveErr := queryProviderLiveStatus(ctx, p, info)
	var liveWarning error
	if liveErr == nil {
		writeTarget, err := liveStatusWriteTarget(instance.Name, sandboxStatusLoadActiveInstance, sandboxStatusForceWrite)
		if err != nil {
			liveErr = fmt.Errorf("load active sandbox %q: %w", instance.Name, err)
		} else if err := persistLiveStatusResult(instance, liveStatus, sandboxStatusNow(), writeTarget); err != nil {
			if _, ok := asLocalStateSyncWarning(err); ok {
				liveWarning = err
			} else {
				liveErr = fmt.Errorf("persist live status: %w", err)
			}
		}
	}

	// Display detailed info
	renderSandboxDetail(out, instance, liveErr, liveWarning)
	if liveErr != nil {
		return fmt.Errorf("live sandbox status for %q: %w", instance.Name, liveErr)
	}

	return nil
}

// renderSandboxDetail renders all SandboxState fields in a detailed view.
func renderSandboxDetail(out io.Writer, inst *sandbox.SandboxState, liveErr, liveWarning error) {
	now := sandboxStatusNow()

	// Identity
	fmt.Fprintf(out, "%s       %s\n", display.StyleBold.Render("Name:"), display.StyleTitle.Render(inst.Name))
	fmt.Fprintf(out, "%s         %s\n", display.StyleBold.Render("ID:"), display.StyleMuted.Render(inst.ID))
	fmt.Fprintf(out, "%s   %s\n", display.StyleBold.Render("Provider:"), inst.Provider)

	// Status with color
	var statusText string
	switch inst.Status {
	case sandbox.StatusRunning:
		statusText = display.StyleSuccess.Render(string(inst.Status))
	case sandbox.StatusStopped:
		statusText = display.StyleWarning.Render(string(inst.Status))
	default:
		statusText = display.StyleMuted.Render(string(inst.Status))
	}
	fmt.Fprintf(out, "%s     %s\n", display.StyleBold.Render("Status:"), statusText)

	if liveErr != nil {
		fmt.Fprintf(out, "Live query: %s\n", display.StyleError.Render(fmt.Sprintf("failed (%s)", liveErr)))
	} else {
		fmt.Fprintf(out, "Live query: %s\n", display.StyleSuccess.Render("status refreshed"))
		fmt.Fprintf(out, "Note:       %s\n", display.StyleMuted.Render("Non-status details below are cached from the registry."))
	}
	if liveWarning != nil {
		fmt.Fprintf(out, "Warning:    %s\n", display.StyleWarning.Render(formatLocalStateSyncWarning(liveWarning)))
	}

	fmt.Fprintln(out)

	// Networking
	fmt.Fprintf(out, "%s\n", display.StyleBold.Render("Networking:"))
	if inst.IP != "" {
		fmt.Fprintf(out, "  Public IP:          %s\n", display.StyleInfo.Render(inst.IP))
	} else {
		fmt.Fprintf(out, "  Public IP:          %s\n", display.StyleMuted.Render("—"))
	}
	if inst.TailscaleIP != "" {
		fmt.Fprintf(out, "  Tailscale IP:       %s\n", display.StyleInfo.Render(inst.TailscaleIP))
	} else {
		fmt.Fprintf(out, "  Tailscale IP:       %s\n", display.StyleMuted.Render("—"))
	}
	if inst.TailscaleHostname != "" {
		fmt.Fprintf(out, "  Tailscale Hostname: %s\n", inst.TailscaleHostname)
	}
	preferredIP := sandbox.PreferredIP(inst)
	if preferredIP != "" {
		fmt.Fprintf(out, "  Active SSH IP:      %s\n", display.StyleSuccess.Render(preferredIP))
	}

	if inst.WorkspaceID != "" {
		fmt.Fprintf(out, "  Workspace ID:       %s\n", display.StyleMuted.Render(inst.WorkspaceID))
	}

	fmt.Fprintln(out)

	// Lifecycle
	fmt.Fprintf(out, "%s\n", display.StyleBold.Render("Lifecycle:"))
	if inst.CreatedAt.IsZero() {
		fmt.Fprintf(out, "  Created:      %s\n", display.StyleMuted.Render("unknown"))
	} else {
		fmt.Fprintf(out, "  Created:      %s %s\n", inst.CreatedAt.Format(time.RFC3339), display.StyleMuted.Render(fmt.Sprintf("(%s ago)", formatAge(now.Sub(inst.CreatedAt)))))
	}
	if inst.StoppedAt != nil {
		if inst.StoppedAt.IsZero() {
			fmt.Fprintf(out, "  Stopped:      %s\n", display.StyleMuted.Render("unknown"))
		} else {
			fmt.Fprintf(out, "  Stopped:      %s %s\n", inst.StoppedAt.Format(time.RFC3339), display.StyleMuted.Render(fmt.Sprintf("(%s ago)", formatAge(now.Sub(*inst.StoppedAt)))))
		}
	}

	fmt.Fprintln(out)

	// Config
	fmt.Fprintf(out, "%s\n", display.StyleBold.Render("Config:"))
	if inst.AutoShutdown {
		fmt.Fprintf(out, "  Auto-shutdown: %s %s\n", display.StyleSuccess.Render("on"), display.StyleMuted.Render(fmt.Sprintf("(%dh idle)", inst.IdleHours)))
	} else {
		fmt.Fprintf(out, "  Auto-shutdown: %s\n", display.StyleMuted.Render("off"))
	}
	if inst.Size != "" {
		fmt.Fprintf(out, "  Size:          %s\n", inst.Size)
	}

	// Cost
	cost := sandbox.EstimatedCost(inst, func() time.Time { return now })
	if cost >= 0 {
		fmt.Fprintf(out, "  Est. cost:     %s\n", display.StyleWarning.Render(fmt.Sprintf("$%.2f", cost)))
	}

	// Labels
	if inst.Repo != "" || inst.SnapshotID != "" {
		fmt.Fprintln(out)
		fmt.Fprintf(out, "%s\n", display.StyleBold.Render("Labels:"))
		if inst.Repo != "" {
			fmt.Fprintf(out, "  Repo:       %s\n", inst.Repo)
		}
		if inst.SnapshotID != "" {
			fmt.Fprintf(out, "  Snapshot:   %s\n", display.StyleMuted.Render(inst.SnapshotID))
		}
	}
}
