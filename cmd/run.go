package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/jywlabs/hal/internal/loop"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"

	// Register available engines
	_ "github.com/jywlabs/hal/internal/engine/claude"
	_ "github.com/jywlabs/hal/internal/engine/codex"
)

// Run command flags
var (
	// Engine selection
	engineFlag string

	// Execution control
	maxRetries int
	retryDelay time.Duration

	// New flags
	dryRunFlag bool
	storyFlag  string
)

var runCmd = &cobra.Command{
	Use:   "run [iterations]",
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
  goralph run                          # Run with defaults (10 iterations)
  goralph run 5                        # Run 5 iterations
  goralph run 1 -s US-001              # Run single specific story
  goralph run -e codex                 # Use Codex engine
  goralph run --dry-run                # Show what would execute
`,
	Args: cobra.MaximumNArgs(1),
	RunE: runRun,
}

func init() {
	// Engine selection
	runCmd.Flags().StringVarP(&engineFlag, "engine", "e", "claude", "Engine to use (claude, codex)")

	// Execution control
	runCmd.Flags().IntVar(&maxRetries, "retries", 3, "Max retries per iteration on failure")
	runCmd.Flags().DurationVar(&retryDelay, "retry-delay", 5*time.Second, "Base retry delay")

	// New flags
	runCmd.Flags().BoolVar(&dryRunFlag, "dry-run", false, "Show what would execute without running")
	runCmd.Flags().StringVarP(&storyFlag, "story", "s", "", "Run specific story by ID (e.g., US-001)")

	rootCmd.AddCommand(runCmd)
}

func runRun(cmd *cobra.Command, args []string) error {
	// Parse iterations from positional arg (default: 10)
	iterations := 10
	if len(args) > 0 {
		n, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid iterations: %q (must be a number)", args[0])
		}
		if n < 0 {
			return fmt.Errorf("iterations must be >= 0")
		}
		iterations = n
	}

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
		MaxIterations: iterations,
		Engine:        engineFlag,
		Logger:        os.Stdout,
		RetryDelay:    retryDelay,
		MaxRetries:    maxRetries,
		DryRun:        dryRunFlag,
		StoryID:       storyFlag,
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
