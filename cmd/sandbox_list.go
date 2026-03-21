package cmd

import (
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/spf13/cobra"
)

var sandboxListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all sandboxes",
	Long: `List all sandbox instances from the global registry.

Displays a table with columns: NAME, PROVIDER, STATUS, TAILSCALE, AGE, AUTO-OFF, EST.COST.

Estimated cost is based on embedded hourly rates and time since creation.
Stopped sandboxes still accrue cost (cloud providers charge for allocated resources).
A dash (—) is shown when rate data is unavailable (e.g., Daytona provider).

The default path reads local registry data only and does not call provider APIs.
Use --live to fetch fresh status from each provider before rendering.
Use --json for machine-readable output.`,
	Example: `  hal sandbox list
  hal sandbox list --live
  hal sandbox list --json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSandboxList(os.Stdout)
	},
}

func init() {
	sandboxCmd.AddCommand(sandboxListCmd)
}

// sandboxListNow is injectable for deterministic tests.
var sandboxListNow = func() time.Time { return time.Now() }

// runSandboxList renders the default table view from local registry data.
func runSandboxList(out io.Writer) error {
	instances, err := sandbox.ListInstances()
	if err != nil {
		return fmt.Errorf("listing sandboxes: %w", err)
	}

	if len(instances) == 0 {
		fmt.Fprintln(out, "No sandboxes found. Run 'hal sandbox start' to create one.")
		return nil
	}

	now := sandboxListNow()

	// Render table
	renderSandboxTable(out, instances, now)

	// Render summary
	renderSandboxSummary(out, instances, now)

	return nil
}

// renderSandboxTable renders the sandbox list as a formatted table.
func renderSandboxTable(out io.Writer, instances []*sandbox.SandboxState, now time.Time) {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tPROVIDER\tSTATUS\tTAILSCALE\tAGE\tAUTO-OFF\tEST.COST")

	for _, inst := range instances {
		tailscale := "—"
		if inst.TailscaleIP != "" {
			tailscale = inst.TailscaleIP
		}

		age := formatAge(now.Sub(inst.CreatedAt))

		autoOff := "off"
		if inst.AutoShutdown {
			autoOff = fmt.Sprintf("%dh", inst.IdleHours)
		}

		cost := formatCost(sandbox.EstimatedCost(inst, func() time.Time { return now }))

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			inst.Name,
			inst.Provider,
			inst.Status,
			tailscale,
			age,
			autoOff,
			cost,
		)
	}

	w.Flush()
}

// renderSandboxSummary renders the summary line below the table.
func renderSandboxSummary(out io.Writer, instances []*sandbox.SandboxState, now time.Time) {
	total := len(instances)
	running := 0
	stopped := 0
	totalCost := 0.0
	hasKnownCost := false

	for _, inst := range instances {
		switch inst.Status {
		case sandbox.StatusRunning:
			running++
		case sandbox.StatusStopped:
			stopped++
		}

		cost := sandbox.EstimatedCost(inst, func() time.Time { return now })
		if cost >= 0 {
			totalCost += cost
			hasKnownCost = true
		}
	}

	costStr := "—"
	if hasKnownCost {
		costStr = fmt.Sprintf("$%.2f", totalCost)
	}

	fmt.Fprintf(out, "\n%d sandboxes (%d running, %d stopped)  •  Est. total: %s\n",
		total, running, stopped, costStr)
}

// formatAge formats a duration into a human-readable age string.
// Examples: "2m", "3h", "1d", "5d".
func formatAge(d time.Duration) string {
	if d < 0 {
		return "0m"
	}

	minutes := int(d.Minutes())
	if minutes < 60 {
		return fmt.Sprintf("%dm", minutes)
	}

	hours := int(d.Hours())
	if hours < 24 {
		return fmt.Sprintf("%dh", hours)
	}

	days := int(math.Floor(d.Hours() / 24))
	return fmt.Sprintf("%dd", days)
}

// formatCost formats a cost value for display.
// Returns "—" for unknown costs (-1) and "$X.XX" for known costs.
func formatCost(cost float64) string {
	if cost < 0 {
		return "—"
	}
	return fmt.Sprintf("$%.2f", cost)
}

// updateInstanceStatus updates an instance's status in-place.
// Used by the --live path (US-024) to update status before rendering.
func updateInstanceStatus(inst *sandbox.SandboxState, status string) {
	if strings.TrimSpace(status) != "" {
		inst.Status = status
	}
}
