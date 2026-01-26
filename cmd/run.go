package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jywlabs/goralph/internal/loop"
	"github.com/jywlabs/goralph/internal/template"
	"github.com/spf13/cobra"

	// Register available engines
	_ "github.com/jywlabs/goralph/internal/engine/amp"
	_ "github.com/jywlabs/goralph/internal/engine/claude"
)

// Run command flags
var (
	// Engine selection
	engineFlag string

	// Execution control
	maxIterations int
	maxRetries    int
	retryDelay    time.Duration
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the Ralph loop",
	Long: `Run the Ralph loop to execute tasks from .goralph/prd.json.

The loop spawns fresh AI instances that:
1. Read prd.json and pick the highest priority pending story
2. Implement the story
3. Run quality checks
4. Commit changes
5. Update prd.json to mark story complete
6. Repeat until all stories pass or max iterations reached

Examples:
  goralph run                          # Run with defaults
  goralph run -e claude                # Use Claude Code
  goralph run -e amp                   # Use Amp
  goralph run --max 20                 # Run up to 20 iterations
`,
	RunE: runRun,
}

func init() {
	// Engine selection
	runCmd.Flags().StringVarP(&engineFlag, "engine", "e", "claude", "Engine to use (claude, amp)")

	// Execution control
	runCmd.Flags().IntVar(&maxIterations, "max", 10, "Max iterations (0=unlimited)")
	runCmd.Flags().IntVar(&maxRetries, "retries", 3, "Max retries per iteration on failure")
	runCmd.Flags().DurationVar(&retryDelay, "retry-delay", 5*time.Second, "Base retry delay")

	rootCmd.AddCommand(runCmd)
}

func runRun(cmd *cobra.Command, args []string) error {
	// Check .goralph directory exists
	goralphDir := template.GoralphDir
	if _, err := os.Stat(goralphDir); os.IsNotExist(err) {
		return fmt.Errorf(".goralph/ not found. Run 'goralph init' first")
	}

	// Check prd.json exists
	prdPath := goralphDir + "/prd.json"
	if _, err := os.Stat(prdPath); os.IsNotExist(err) {
		return fmt.Errorf("prd.json not found at %s. Create your task list first", prdPath)
	}

	// Create and run the loop
	runner, err := loop.New(loop.Config{
		Dir:           goralphDir,
		MaxIterations: maxIterations,
		Engine:        engineFlag,
		Logger:        os.Stdout,
		RetryDelay:    retryDelay,
		MaxRetries:    maxRetries,
	})
	if err != nil {
		return err
	}

	result := runner.Run(context.Background())

	// Only return error if there was an actual failure
	if result.Error != nil {
		return fmt.Errorf("loop failed: %w", result.Error)
	}

	return nil
}
