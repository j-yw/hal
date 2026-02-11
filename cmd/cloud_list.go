package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
	"github.com/jywlabs/hal/internal/cloud/deploy"
	"github.com/spf13/cobra"
)

// Cloud list flags.
var (
	cloudListJSONFlag bool
)

var cloudListCmd = &cobra.Command{
	Use:   "list",
	Short: "List cloud runs",
	Long: `List recent cloud runs ordered by last updated timestamp.

Returns up to 20 runs including run ID, workflow kind, status, and updated timestamp.
Use --json for machine-readable output.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCloudList(
			cloudListJSONFlag,
			cloudListStoreFactory,
			os.Stdout,
		)
	},
}

// cloudListStoreFactory is a package-level variable that tests can override.
var cloudListStoreFactory func() (cloud.Store, error)

func init() {
	cloudListCmd.Flags().BoolVar(&cloudListJSONFlag, "json", false, "Output in JSON format")

	cloudCmd.AddCommand(cloudListCmd)

	if cloudListStoreFactory == nil {
		cloudListStoreFactory = deploy.DefaultStoreFactory
	}
}

// cloudListRunEntry is a single run entry in the list response.
type cloudListRunEntry struct {
	RunID        string `json:"run_id"`
	WorkflowKind string `json:"workflow_kind"`
	Status       string `json:"status"`
	UpdatedAt    string `json:"updated_at"`
}

// cloudListResponse is the JSON output for a successful list.
type cloudListResponse struct {
	Runs []cloudListRunEntry `json:"runs"`
}

// runCloudList is the testable logic for the cloud list command.
func runCloudList(
	jsonOutput bool,
	storeFactory func() (cloud.Store, error),
	out io.Writer,
) error {
	if storeFactory == nil {
		return writeCloudError(out, jsonOutput, "store not configured", "configuration_error")
	}

	store, err := storeFactory()
	if err != nil {
		return writeCloudError(out, jsonOutput, fmt.Sprintf("failed to connect to store: %v", err), "configuration_error")
	}

	ctx := context.Background()
	runs, err := store.ListRuns(ctx, 20)
	if err != nil {
		return writeCloudError(out, jsonOutput, fmt.Sprintf("failed to list runs: %v", err), "store_error")
	}

	if jsonOutput {
		entries := make([]cloudListRunEntry, len(runs))
		for i, r := range runs {
			entries[i] = cloudListRunEntry{
				RunID:        r.ID,
				WorkflowKind: string(r.WorkflowKind),
				Status:       string(r.Status),
				UpdatedAt:    r.UpdatedAt.Format(time.RFC3339),
			}
		}
		return writeJSON(out, cloudListResponse{Runs: entries})
	}

	// Human-readable output.
	if len(runs) == 0 {
		fmt.Fprintf(out, "No cloud runs found.\n")
		return nil
	}

	fmt.Fprintf(out, "Recent cloud runs:\n")
	for _, r := range runs {
		fmt.Fprintf(out, "  %-36s  %-8s  %-10s  %s\n",
			r.ID,
			r.WorkflowKind,
			r.Status,
			r.UpdatedAt.Format(time.RFC3339),
		)
	}
	return nil
}
