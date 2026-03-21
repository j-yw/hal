package cmd

import (
	"encoding/json"
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

var sandboxListJSONFlag bool

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
Use --json for machine-readable output following the sandbox-list-v1 contract.`,
	Example: `  hal sandbox list
  hal sandbox list --live
  hal sandbox list --json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		jsonMode := sandboxListJSONFlag
		if cmd != nil {
			if f := cmd.Flags().Lookup("json"); f != nil {
				v, err := cmd.Flags().GetBool("json")
				if err == nil {
					jsonMode = v
				}
			}
		}
		return runSandboxList(os.Stdout, jsonMode)
	},
}

func init() {
	sandboxListCmd.Flags().BoolVar(&sandboxListJSONFlag, "json", false, "Output machine-readable JSON (sandbox-list-v1 contract)")
	sandboxCmd.AddCommand(sandboxListCmd)
}

// sandboxListNow is injectable for deterministic tests.
var sandboxListNow = func() time.Time { return time.Now() }

// SandboxListResponse is the machine-readable JSON output for hal sandbox list --json.
// Follows the sandbox-list-v1 contract.
type SandboxListResponse struct {
	ContractVersion string              `json:"contractVersion"`
	Sandboxes       []SandboxListEntry  `json:"sandboxes"`
	Totals          SandboxListTotals   `json:"totals"`
}

// SandboxListEntry represents one sandbox in the JSON list output.
type SandboxListEntry struct {
	// Required fields
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Provider  string    `json:"provider"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`

	// Optional fields
	WorkspaceID       string     `json:"workspaceId,omitempty"`
	IP                string     `json:"ip,omitempty"`
	TailscaleIP       string     `json:"tailscaleIp,omitempty"`
	TailscaleHostname string     `json:"tailscaleHostname,omitempty"`
	StoppedAt         *time.Time `json:"stoppedAt,omitempty"`
	AutoShutdown      bool       `json:"autoShutdown,omitempty"`
	IdleHours         int        `json:"idleHours,omitempty"`
	Size              string     `json:"size,omitempty"`
	Repo              string     `json:"repo,omitempty"`
	SnapshotID        string     `json:"snapshotId,omitempty"`
	EstimatedCost     *float64   `json:"estimatedCost,omitempty"`
}

// SandboxListTotals holds aggregate counts for the JSON list output.
type SandboxListTotals struct {
	Total         int      `json:"total"`
	Running       int      `json:"running"`
	Stopped       int      `json:"stopped"`
	EstimatedCost *float64 `json:"estimatedCost,omitempty"`
}

// runSandboxList renders sandbox list as table (default) or JSON (--json).
func runSandboxList(out io.Writer, jsonMode bool) error {
	instances, err := sandbox.ListInstances()
	if err != nil {
		return fmt.Errorf("listing sandboxes: %w", err)
	}

	now := sandboxListNow()

	if jsonMode {
		return renderSandboxListJSON(out, instances, now)
	}

	if len(instances) == 0 {
		fmt.Fprintln(out, "No sandboxes found. Run 'hal sandbox start' to create one.")
		return nil
	}

	// Render table
	renderSandboxTable(out, instances, now)

	// Render summary
	renderSandboxSummary(out, instances, now)

	return nil
}

// renderSandboxListJSON renders the sandbox list as machine-readable JSON.
func renderSandboxListJSON(out io.Writer, instances []*sandbox.SandboxState, now time.Time) error {
	nowFn := func() time.Time { return now }

	entries := make([]SandboxListEntry, 0, len(instances))
	totalRunning := 0
	totalStopped := 0
	totalCost := 0.0
	hasKnownCost := false

	for _, inst := range instances {
		entry := SandboxListEntry{
			ID:                inst.ID,
			Name:              inst.Name,
			Provider:          inst.Provider,
			Status:            inst.Status,
			CreatedAt:         inst.CreatedAt,
			WorkspaceID:       inst.WorkspaceID,
			IP:                inst.IP,
			TailscaleIP:       inst.TailscaleIP,
			TailscaleHostname: inst.TailscaleHostname,
			StoppedAt:         inst.StoppedAt,
			AutoShutdown:      inst.AutoShutdown,
			IdleHours:         inst.IdleHours,
			Size:              inst.Size,
			Repo:              inst.Repo,
			SnapshotID:        inst.SnapshotID,
		}

		cost := sandbox.EstimatedCost(inst, nowFn)
		if cost >= 0 {
			c := math.Round(cost*100) / 100
			entry.EstimatedCost = &c
			totalCost += cost
			hasKnownCost = true
		}

		entries = append(entries, entry)

		switch inst.Status {
		case sandbox.StatusRunning:
			totalRunning++
		case sandbox.StatusStopped:
			totalStopped++
		}
	}

	totals := SandboxListTotals{
		Total:   len(instances),
		Running: totalRunning,
		Stopped: totalStopped,
	}
	if hasKnownCost {
		c := math.Round(totalCost*100) / 100
		totals.EstimatedCost = &c
	}

	resp := SandboxListResponse{
		ContractVersion: "sandbox-list-v1",
		Sandboxes:       entries,
		Totals:          totals,
	}

	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal sandbox list: %w", err)
	}

	fmt.Fprintln(out, string(data))
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
