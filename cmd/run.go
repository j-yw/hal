package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
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

	// Iteration control
	runIterationsFlag int

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
  hal run 5                        # Run 5 iterations (positional)
  hal run -i 5                     # Run 5 iterations (flag)
  hal run 1 -s US-001              # Run single specific story
  hal run -e codex                 # Use Codex engine
  hal run --dry-run                # Show what would execute
  hal run --base develop           # Branch from develop when needed
`,
	Args: maxArgsValidation(1),
	RunE: runRun,
}

func init() {
	// Engine selection
	runCmd.Flags().StringVarP(&engineFlag, "engine", "e", "codex", "Engine to use (claude, codex, pi)")

	// Execution control
	runCmd.Flags().IntVar(&maxRetries, "retries", 3, "Max retries per iteration on failure")
	runCmd.Flags().DurationVar(&retryDelay, "retry-delay", 5*time.Second, "Base retry delay")

	// Iteration control
	runCmd.Flags().IntVarP(&runIterationsFlag, "iterations", "i", 10, "Maximum iterations to run")

	// Additional options
	runCmd.Flags().BoolVar(&dryRunFlag, "dry-run", false, "Show what would execute without running")
	runCmd.Flags().StringVarP(&storyFlag, "story", "s", "", "Run specific story by ID (e.g., US-001)")
	runCmd.Flags().StringVarP(&runBaseFlag, "base", "b", "", "Base branch for creating the PRD branch (default: current branch, or HEAD when detached)")

	rootCmd.AddCommand(runCmd)
}

func runRun(cmd *cobra.Command, args []string) error {
	return runRunWithWriter(cmd, args, nil)
}

func runRunWithWriter(cmd *cobra.Command, args []string, errOut io.Writer) error {
	out := io.Writer(os.Stdout)
	if cmd != nil {
		out = cmd.OutOrStdout()
		if errOut == nil {
			errOut = cmd.ErrOrStderr()
		}
	}
	if errOut == nil {
		errOut = os.Stderr
	}

	engineName := engineFlag
	iterationsFlag := runIterationsFlag
	iterationsChanged := false
	baseFlag := runBaseFlag
	retries := maxRetries
	delay := retryDelay
	dryRun := dryRunFlag
	story := storyFlag

	if cmd != nil {
		flags := cmd.Flags()

		if flags.Lookup("engine") != nil {
			value, err := flags.GetString("engine")
			if err != nil {
				return err
			}
			engineName = value
		}

		if flags.Lookup("iterations") != nil {
			value, err := flags.GetInt("iterations")
			if err != nil {
				return err
			}
			iterationsFlag = value
			iterationsChanged = flags.Changed("iterations")
		}

		if flags.Lookup("base") != nil {
			value, err := flags.GetString("base")
			if err != nil {
				return err
			}
			baseFlag = value
		}

		if flags.Lookup("retries") != nil {
			value, err := flags.GetInt("retries")
			if err != nil {
				return err
			}
			retries = value
		}

		if flags.Lookup("retry-delay") != nil {
			value, err := flags.GetDuration("retry-delay")
			if err != nil {
				return err
			}
			delay = value
		}

		if flags.Lookup("dry-run") != nil {
			value, err := flags.GetBool("dry-run")
			if err != nil {
				return err
			}
			dryRun = value
		}

		if flags.Lookup("story") != nil {
			value, err := flags.GetString("story")
			if err != nil {
				return err
			}
			story = value
		}
	}

	iterations, err := parseIterations(args, iterationsFlag, iterationsChanged, 10)
	if err != nil {
		return exitWithCode(cmd, ExitCodeValidation, err)
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

	baseBranch := compound.ResolveBaseBranch(
		baseFlag,
		compound.CurrentBranchOptional,
		func(format string, args ...any) {
			fmt.Fprintf(errOut, format, args...)
		},
	)

	resolvedEngine, err := resolveEngine(cmd, "engine", engineName, ".")
	if err != nil {
		return exitWithCode(cmd, ExitCodeValidation, err)
	}

	// Create and run the loop
	runner, err := loop.New(loop.Config{
		Dir:           halDir,
		MaxIterations: iterations,
		Engine:        resolvedEngine,
		EngineConfig:  compound.LoadEngineConfig(".", resolvedEngine),
		Logger:        out,
		RetryDelay:    delay,
		MaxRetries:    retries,
		DryRun:        dryRun,
		StoryID:       story,
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
