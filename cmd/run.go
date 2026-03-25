package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/engine"
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
	runTimeout time.Duration

	// Iteration control
	runIterationsFlag int

	// New flags
	dryRunFlag  bool
	storyFlag   string
	runBaseFlag string
	runJSONFlag bool
)

// RunResult is the machine-readable output of hal run --json.
type RunResult struct {
	ContractVersion int            `json:"contractVersion"`
	OK              bool           `json:"ok"`
	Iterations      int            `json:"iterations"`
	Complete        bool           `json:"complete"`
	StoryID         string         `json:"storyId,omitempty"`
	DryRun          bool           `json:"dryRun,omitempty"`
	Duration        string         `json:"duration,omitempty"`
	PRD             *RunPRDInfo    `json:"prd,omitempty"`
	NextAction      *RunNextAction `json:"nextAction,omitempty"`
	Error           string         `json:"error,omitempty"`
	Summary         string         `json:"summary"`
}

// RunPRDInfo provides PRD state at the time the run completed.
type RunPRDInfo struct {
	Path             string `json:"path"`
	CompletedStories int    `json:"completedStories"`
	TotalStories     int    `json:"totalStories"`
}

// RunNextAction suggests what to do after the run.
type RunNextAction struct {
	ID          string `json:"id"`
	Command     string `json:"command"`
	Description string `json:"description"`
}

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

With --json, outputs a stable machine-readable result contract suitable
for agent orchestration and tooling integration.

Examples:
  hal run                          # Run with defaults (10 iterations)
  hal run 5                        # Run 5 iterations (positional)
  hal run -i 5                     # Run 5 iterations (flag)
  hal run 1 -s US-001              # Run single specific story
  hal run -e codex                 # Use Codex engine
  hal run --timeout 30m            # Override per-session engine timeout
  hal run --dry-run                # Show what would execute
  hal run --base develop           # Branch from develop when needed
  hal run --json                   # Machine-readable result output
`,
	Example: `  hal run
  hal run 5
  hal run --story US-001
  hal run --timeout 30m
  hal run --json
  hal run --engine codex --base develop`,
	Args: maxArgsValidation(1),
	RunE: runRun,
}

func init() {
	// Engine selection
	runCmd.Flags().StringVarP(&engineFlag, "engine", "e", "codex", "Engine to use (claude, codex, pi)")

	// Execution control
	runCmd.Flags().IntVar(&maxRetries, "retries", 3, "Max retries per iteration on failure")
	runCmd.Flags().DurationVar(&retryDelay, "retry-delay", 5*time.Second, "Base retry delay")
	runCmd.Flags().DurationVar(&runTimeout, "timeout", 0, "Per-engine session timeout override (e.g., 30m, 1h)")

	// Iteration control
	runCmd.Flags().IntVarP(&runIterationsFlag, "iterations", "i", 10, "Maximum iterations to run")

	// Additional options
	runCmd.Flags().BoolVar(&dryRunFlag, "dry-run", false, "Show what would execute without running")
	runCmd.Flags().StringVarP(&storyFlag, "story", "s", "", "Run specific story by ID (e.g., US-001)")
	runCmd.Flags().StringVarP(&runBaseFlag, "base", "b", "", "Base branch for creating the PRD branch (default: current branch, or HEAD when detached)")
	runCmd.Flags().BoolVar(&runJSONFlag, "json", false, "Output machine-readable JSON result")

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
	timeoutOverride := runTimeout
	dryRun := dryRunFlag
	story := storyFlag
	jsonMode := runJSONFlag

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

		if flags.Lookup("timeout") != nil {
			value, err := flags.GetDuration("timeout")
			if err != nil {
				return err
			}
			timeoutOverride = value
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

		if flags.Lookup("json") != nil {
			value, err := flags.GetBool("json")
			if err != nil {
				return err
			}
			jsonMode = value
		}
	}

	iterations, err := parseIterations(args, iterationsFlag, iterationsChanged, 10)
	if err != nil {
		if jsonMode {
			return outputRunJSONError(out, err.Error())
		}
		return exitWithCode(cmd, ExitCodeValidation, err)
	}
	if timeoutOverride < 0 {
		if jsonMode {
			return outputRunJSONError(out, "--timeout must be greater than or equal to 0")
		}
		return exitWithCode(cmd, ExitCodeValidation, fmt.Errorf("--timeout must be greater than or equal to 0"))
	}

	// Check .hal directory exists
	halDir := template.HalDir
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		if jsonMode {
			return outputRunJSONError(out, ".hal/ not found. Run 'hal init' first")
		}
		return fmt.Errorf(".hal/ not found. Run 'hal init' first")
	}

	// Check prd.json exists
	prdPath := halDir + "/prd.json"
	if _, err := os.Stat(prdPath); os.IsNotExist(err) {
		if jsonMode {
			return outputRunJSONError(out, "prd.json not found at "+prdPath+". Create your task list first")
		}
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
		if jsonMode {
			return outputRunJSONError(out, err.Error())
		}
		return exitWithCode(cmd, ExitCodeValidation, err)
	}
	engineCfg := compound.LoadEngineConfig(".", resolvedEngine)
	if timeoutOverride > 0 {
		engineCfg = withTimeoutOverride(engineCfg, timeoutOverride)
	}

	// Create and run the loop
	runner, err := loop.New(loop.Config{
		Dir:           halDir,
		MaxIterations: iterations,
		Engine:        resolvedEngine,
		EngineConfig:  engineCfg,
		Logger:        out,
		RetryDelay:    delay,
		MaxRetries:    retries,
		DryRun:        dryRun,
		StoryID:       story,
		BaseBranch:    baseBranch,
	})
	if err != nil {
		if jsonMode {
			return outputRunJSONError(out, err.Error())
		}
		return err
	}

	result := runner.Run(context.Background())

	if jsonMode {
		return outputRunJSON(out, result, story, dryRun)
	}

	// Show completion summary in terminal mode
	showRunSummary(out, result)

	// Only return error if there was an actual failure
	if result.Error != nil {
		return fmt.Errorf("loop failed: %w", result.Error)
	}

	return nil
}

// showRunSummary renders a human-readable completion summary after the loop finishes.
func showRunSummary(out io.Writer, result loop.Result) {
	fmt.Fprintln(out)
	if result.Complete {
		fmt.Fprintf(out, "%s All stories complete after %d iteration(s).\n",
			engine.StyleSuccess.Render("✓"), result.Iterations)
	} else if result.Success {
		fmt.Fprintf(out, "%s Completed %d iteration(s). Stories remain.\n",
			engine.StyleInfo.Render("→"), result.Iterations)
	}

	// Show elapsed time
	if result.Duration > 0 {
		fmt.Fprintf(out, "%s %s\n",
			engine.StyleBold.Render("Duration:"), formatRunDuration(result.Duration))
	}

	// Show PRD progress if available
	prdPath := filepath.Join(template.HalDir, template.PRDFile)
	if prd, err := engine.LoadPRDFile(template.HalDir, template.PRDFile); err == nil {
		completed, total := prd.Progress()
		fmt.Fprintf(out, "%s Progress: %d/%d stories complete",
			engine.StyleBold.Render("PRD:"), completed, total)
		if total > 0 {
			pct := completed * 100 / total
			fmt.Fprintf(out, " (%d%%)", pct)
		}
		fmt.Fprintln(out)
		_ = prdPath // used for Progress call context
	}
}

// formatRunDuration renders a duration as a human-friendly string.
func formatRunDuration(d time.Duration) string {
	d = d.Round(time.Second)
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func outputRunJSONError(out io.Writer, errMsg string) error {
	jr := RunResult{
		ContractVersion: 1,
		OK:              false,
		Error:           errMsg,
		Summary:         errMsg,
	}
	data, _ := json.MarshalIndent(jr, "", "  ")
	fmt.Fprintln(out, string(data))
	return nil
}

func outputRunJSON(out io.Writer, result loop.Result, storyID string, dryRun bool) error {
	jr := RunResult{
		ContractVersion: 1,
		OK:              result.Success,
		Iterations:      result.Iterations,
		StoryID:         storyID,
		DryRun:          dryRun,
		Complete:        result.Complete,
	}
	if result.Duration > 0 {
		jr.Duration = result.Duration.Round(time.Second).String()
	}

	// Try to read PRD state post-loop
	prdPath := filepath.Join(template.HalDir, template.PRDFile)
	if prd, err := engine.LoadPRDFile(template.HalDir, template.PRDFile); err == nil {
		completed, total := prd.Progress()
		jr.PRD = &RunPRDInfo{
			Path:             prdPath,
			CompletedStories: completed,
			TotalStories:     total,
		}
	}

	if result.Error != nil {
		jr.Error = result.Error.Error()
	}

	if result.Complete {
		jr.Summary = fmt.Sprintf("All stories complete after %d iteration(s).", result.Iterations)
		jr.NextAction = &RunNextAction{
			ID:          "run_report",
			Command:     "hal report",
			Description: "Generate a report for the completed work.",
		}
	} else if result.Success {
		jr.Summary = fmt.Sprintf("Completed %d iteration(s). Stories remain.", result.Iterations)
		jr.NextAction = &RunNextAction{
			ID:          "run_manual",
			Command:     "hal run",
			Description: "Continue executing the remaining stories.",
		}
	} else {
		jr.Summary = fmt.Sprintf("Failed after %d iteration(s).", result.Iterations)
		jr.NextAction = &RunNextAction{
			ID:          "run_manual",
			Command:     "hal run",
			Description: "Retry the run.",
		}
	}

	data, err := json.MarshalIndent(jr, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal run result: %w", err)
	}
	fmt.Fprintln(out, string(data))
	return nil
}

func withTimeoutOverride(cfg *engine.EngineConfig, timeout time.Duration) *engine.EngineConfig {
	if timeout <= 0 {
		return cfg
	}

	merged := &engine.EngineConfig{Timeout: timeout}
	if cfg == nil {
		return merged
	}

	merged.Model = cfg.Model
	merged.Provider = cfg.Provider
	return merged
}
