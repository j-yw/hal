package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/spf13/cobra"
)

const FactoryListContractVersion = "factory-list-v1"

var factoryListJSONFlag bool

var factoryCmd = &cobra.Command{
	Use:   "factory",
	Short: "Inspect factory run history",
	Long: `Inspect durable factory run history stored under Hal's global config directory.

Factory commands read the global factory store, which is separate from per-project
.hal runtime state. Use the list command to inspect stored run summaries.`,
	Example: `  hal factory list
  hal factory list --json`,
}

var factoryListCmd = &cobra.Command{
	Use:   "list",
	Short: "List stored factory runs",
	Args:  noArgsValidation(),
	Long: `List stored factory runs from the global factory store.

The default output is a compact table of run IDs, statuses, branches, steps,
and update timestamps. Use --json for machine-readable output following the
factory-list-v1 contract. JSON output includes run summaries only; event
timelines are intentionally omitted from the list surface.`,
	Example: `  hal factory list
  hal factory list --json`,
	RunE: runFactoryList,
}

func init() {
	factoryListCmd.Flags().BoolVar(&factoryListJSONFlag, "json", false, "Output machine-readable JSON (factory-list-v1 contract)")
	factoryCmd.AddCommand(factoryListCmd)
	rootCmd.AddCommand(factoryCmd)
}

type factoryListDeps struct {
	defaultStore func() (factory.Store, error)
}

var defaultFactoryListDeps = factoryListDeps{
	defaultStore: factory.DefaultStore,
}

// FactoryListResponse is the machine-readable JSON output for hal factory list --json.
type FactoryListResponse struct {
	ContractVersion string              `json:"contractVersion"`
	Runs            []FactoryRunSummary `json:"runs"`
}

// FactoryRunSummary is the list surface for one factory run. It intentionally
// excludes full artifact records and event timelines so list output stays small.
type FactoryRunSummary struct {
	RunID         string                  `json:"runId"`
	Status        string                  `json:"status"`
	Source        factory.SourceMetadata  `json:"source"`
	RepoPath      string                  `json:"repoPath"`
	RepoRemote    string                  `json:"repoRemote"`
	BranchName    string                  `json:"branchName"`
	BaseBranch    string                  `json:"baseBranch"`
	SandboxName   string                  `json:"sandboxName,omitempty"`
	CurrentStep   string                  `json:"currentStep"`
	CreatedAt     time.Time               `json:"createdAt"`
	UpdatedAt     time.Time               `json:"updatedAt"`
	FinishedAt    *time.Time              `json:"finishedAt,omitempty"`
	ArtifactCount int                     `json:"artifactCount"`
	Failure       *factory.FailureSummary `json:"failure,omitempty"`
}

func runFactoryList(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	jsonMode := factoryListJSONFlag

	if cmd != nil {
		out = cmd.OutOrStdout()
		if cmd.Flags().Lookup("json") != nil {
			v, err := cmd.Flags().GetBool("json")
			if err != nil {
				return err
			}
			jsonMode = v
		}
	}

	return runFactoryListWithDeps(out, jsonMode, defaultFactoryListDeps)
}

func runFactoryListWithDeps(out io.Writer, jsonMode bool, deps factoryListDeps) error {
	if out == nil {
		out = io.Discard
	}
	if deps.defaultStore == nil {
		return fmt.Errorf("factory store dependency is required")
	}

	store, err := deps.defaultStore()
	if err != nil {
		return fmt.Errorf("open factory store: %w", err)
	}
	records, err := store.ListRuns()
	if err != nil {
		return fmt.Errorf("list factory runs: %w", err)
	}

	if jsonMode {
		return renderFactoryListJSON(out, records)
	}

	renderFactoryListTable(out, records)
	return nil
}

func renderFactoryListJSON(out io.Writer, records []factory.RunRecord) error {
	summaries := make([]FactoryRunSummary, 0, len(records))
	for _, record := range records {
		summaries = append(summaries, summarizeFactoryRun(record))
	}

	resp := FactoryListResponse{
		ContractVersion: FactoryListContractVersion,
		Runs:            summaries,
	}
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal factory list: %w", err)
	}
	fmt.Fprintln(out, string(data))
	return nil
}

func summarizeFactoryRun(record factory.RunRecord) FactoryRunSummary {
	return FactoryRunSummary{
		RunID:         record.RunID,
		Status:        record.Status,
		Source:        record.Source,
		RepoPath:      record.RepoPath,
		RepoRemote:    record.RepoRemote,
		BranchName:    record.BranchName,
		BaseBranch:    record.BaseBranch,
		SandboxName:   record.SandboxName,
		CurrentStep:   record.CurrentStep,
		CreatedAt:     record.CreatedAt,
		UpdatedAt:     record.UpdatedAt,
		FinishedAt:    record.FinishedAt,
		ArtifactCount: len(record.Artifacts),
		Failure:       record.Failure,
	}
}

func renderFactoryListTable(out io.Writer, records []factory.RunRecord) {
	if len(records) == 0 {
		fmt.Fprintln(out, "No factory runs found.")
		return
	}

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "RUN ID\tSTATUS\tBRANCH\tSTEP\tUPDATED")
	for _, record := range records {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			record.RunID,
			record.Status,
			record.BranchName,
			record.CurrentStep,
			formatFactoryListTime(record.UpdatedAt),
		)
	}
	_ = w.Flush()
}

func formatFactoryListTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}
