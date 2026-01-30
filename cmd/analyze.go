package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jywlabs/goralph/internal/compound"
	"github.com/jywlabs/goralph/internal/engine"
	"github.com/jywlabs/goralph/internal/template"
	"github.com/spf13/cobra"

	// Register available engines
	_ "github.com/jywlabs/goralph/internal/engine/claude"
	_ "github.com/jywlabs/goralph/internal/engine/codex"
)

var (
	analyzeReportsDirFlag string
	analyzeOutputFlag     string
	analyzeEngineFlag     string
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze [report-path]",
	Short: "Analyze a report to identify the highest priority item",
	Long: `Analyze a product/engineering report to identify the highest priority item.

By default, looks for the most recently modified file in .goralph/reports/.
You can specify a report file path directly as an argument.

The analysis returns:
  - Priority item title
  - Description of what needs to be built
  - Rationale for prioritization
  - Estimated number of tasks
  - Suggested branch name

Examples:
  goralph analyze                           # Analyze latest report
  goralph analyze report.md                 # Analyze specific file
  goralph analyze --reports-dir ./reports   # Use custom reports directory
  goralph analyze --output json             # Output as JSON`,
	Args: cobra.MaximumNArgs(1),
	RunE: runAnalyze,
}

func init() {
	analyzeCmd.Flags().StringVar(&analyzeReportsDirFlag, "reports-dir", "", "Directory containing reports (overrides config)")
	analyzeCmd.Flags().StringVarP(&analyzeOutputFlag, "output", "o", "text", "Output format: text (default) or json")
	analyzeCmd.Flags().StringVarP(&analyzeEngineFlag, "engine", "e", "claude", "Engine to use (claude, codex)")
	rootCmd.AddCommand(analyzeCmd)
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	dir := "."

	// Load config for default reports directory
	config, err := compound.LoadConfig(dir)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Determine reports directory
	reportsDir := config.ReportsDir
	if analyzeReportsDirFlag != "" {
		reportsDir = analyzeReportsDirFlag
	}

	// Determine report path
	var reportPath string
	if len(args) > 0 {
		// User provided specific report path
		reportPath = args[0]
		if _, err := os.Stat(reportPath); os.IsNotExist(err) {
			return fmt.Errorf("report file not found: %s", reportPath)
		}
	} else {
		// Find latest report in reports directory
		var err error
		reportPath, err = compound.FindLatestReport(reportsDir)
		if err != nil {
			// Handle no reports found gracefully
			fmt.Println("No reports found.")
			fmt.Println()
			fmt.Printf("Place your reports in %s/ and run this command again.\n", reportsDir)
			fmt.Println("Reports can be markdown files, text files, or any format the AI can analyze.")
			return nil
		}
	}

	// Create engine
	eng, err := engine.New(analyzeEngineFlag)
	if err != nil {
		return fmt.Errorf("failed to create engine: %w", err)
	}

	// Create display
	display := engine.NewDisplay(os.Stdout)

	// Show command header
	display.ShowCommandHeader("Analyze", filepath.Base(reportPath), eng.Name())

	// Find recent PRDs to avoid duplicating work
	goralphDir := template.GoralphDir
	recentPRDs, err := compound.FindRecentPRDs(dir, 7) // Last 7 days
	if err != nil {
		// Non-fatal - just log and continue
		fmt.Fprintf(os.Stderr, "Warning: could not find recent PRDs: %v\n", err)
		recentPRDs = nil
	}

	// Analyze the report
	result, err := compound.AnalyzeReport(ctx, eng, reportPath, recentPRDs)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	// Output result
	if analyzeOutputFlag == "json" {
		return outputAnalysisJSON(result)
	}
	return outputAnalysisText(result, goralphDir, config.BranchPrefix)
}

func outputAnalysisJSON(result *compound.AnalysisResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

func outputAnalysisText(result *compound.AnalysisResult, goralphDir string, branchPrefix string) error {
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  ANALYSIS RESULT")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	fmt.Printf("  Priority Item:    %s\n", result.PriorityItem)
	fmt.Println()

	fmt.Println("  Description:")
	fmt.Printf("    %s\n", result.Description)
	fmt.Println()

	fmt.Println("  Rationale:")
	fmt.Printf("    %s\n", result.Rationale)
	fmt.Println()

	if len(result.AcceptanceCriteria) > 0 {
		fmt.Println("  Acceptance Criteria:")
		for _, criterion := range result.AcceptanceCriteria {
			fmt.Printf("    - %s\n", criterion)
		}
		fmt.Println()
	}

	fmt.Printf("  Estimated Tasks:  %d\n", result.EstimatedTasks)
	fmt.Printf("  Suggested Branch: %s%s\n", branchPrefix, result.BranchName)
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	fmt.Println("Next steps:")
	fmt.Printf("  1. goralph auto --report <path>  # Run full pipeline\n")
	fmt.Printf("  2. Or manually create a PRD in %s/\n", goralphDir)
	fmt.Println()

	return nil
}
