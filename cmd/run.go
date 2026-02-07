package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/loop"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

// Run command flags
var (
	// Engine selection
	engineFlag string

	// Execution control
	maxRetries int
	retryDelay time.Duration

	// New flags
	dryRunFlag  bool
	storyFlag   string
	runBaseFlag string
)

var runCmd = &cobra.Command{
	Use:   "run [iterations]",
	Short: "Run the Hal loop",
	Long: `Run the Hal loop to execute tasks from .hal/prd.json.

The loop spawns fresh AI instances that:
1. Read prd.json and pick the highest priority pending story
2. Implement the story
3. Run quality checks
4. Commit changes
5. Update prd.json to mark story complete
6. Repeat until all stories pass or max iterations reached

Examples:
  hal run                          # Run with defaults (10 iterations)
  hal run 5                        # Run 5 iterations
  hal run 1 -s US-001              # Run single specific story
  hal run -e codex                 # Use Codex engine
  hal run --dry-run                # Show what would execute
  hal run --base develop           # Branch from develop when needed
`,
	Args: cobra.MaximumNArgs(1),
	RunE: runRun,
}

func init() {
	// Engine selection
	runCmd.Flags().StringVarP(&engineFlag, "engine", "e", "claude", "Engine to use (claude, codex, pi)")

	// Execution control
	runCmd.Flags().IntVar(&maxRetries, "retries", 3, "Max retries per iteration on failure")
	runCmd.Flags().DurationVar(&retryDelay, "retry-delay", 5*time.Second, "Base retry delay")

	// New flags
	runCmd.Flags().BoolVar(&dryRunFlag, "dry-run", false, "Show what would execute without running")
	runCmd.Flags().StringVarP(&storyFlag, "story", "s", "", "Run specific story by ID (e.g., US-001)")
	runCmd.Flags().StringVar(&runBaseFlag, "base", "", "Base branch for creating the PRD branch (default: current branch, or HEAD when detached)")

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

	// Check .hal directory exists
	halDir := template.HalDir
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		return fmt.Errorf(".hal/ not found. Run 'hal init' first")
	}

	// Check prd.json exists
	prdPath := halDir + "/prd.json"
	if _, err := os.Stat(prdPath); os.IsNotExist(err) {
		return fmt.Errorf("prd.json not found at %s. Create your task list first", prdPath)
	}

	baseBranch, err := resolveRunBaseBranch(runBaseFlag, compound.CurrentBranchOptional)
	if err != nil {
		return err
	}

	// Create and run the loop
	runner, err := loop.New(loop.Config{
		Dir:           halDir,
		MaxIterations: iterations,
		Engine:        engineFlag,
		EngineConfig:  compound.LoadEngineConfig(".", engineFlag),
		Logger:        os.Stdout,
		RetryDelay:    retryDelay,
		MaxRetries:    maxRetries,
		DryRun:        dryRunFlag,
		StoryID:       storyFlag,
		BaseBranch:    baseBranch,
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

func resolveRunBaseBranch(baseFlag string, currentBranchFn func() (string, error)) (string, error) {
	baseBranch := strings.TrimSpace(baseFlag)
	if baseBranch != "" {
		return baseBranch, nil
	}

	baseBranch, err := currentBranchFn()
	if err != nil {
		return "", fmt.Errorf("failed to determine current branch for --base: %w", err)
	}
	return baseBranch, nil
}
