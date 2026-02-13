//go:build integration
// +build integration

package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"slices"
	"testing"

	"github.com/jywlabs/hal/internal/cloud"
)

const (
	workerLifecycleFlowRunIDPlaceholder    = "<run-id>"
	workerLifecycleFlowWorkflowPlaceholder = "<workflow-command>"
)

type workerLifecycleFlowStep struct {
	Name          string
	Args          []string
	RequiresRunID bool
}

type workerLifecycleWorkflowFixture struct {
	Name            string
	WorkflowKind    cloud.WorkflowKind
	WorkflowCommand string
}

// workerLifecycleSharedFlowSteps defines the canonical lifecycle flow once and
// is reused for run/auto/review via workflow placeholder substitution.
var workerLifecycleSharedFlowSteps = []workerLifecycleFlowStep{
	{Name: "setup", Args: []string{"cloud", "setup"}},
	{Name: "submit", Args: []string{workerLifecycleFlowWorkflowPlaceholder, "--cloud"}},
	{Name: "status", Args: []string{"cloud", "status", workerLifecycleFlowRunIDPlaceholder}, RequiresRunID: true},
	{Name: "logs", Args: []string{"cloud", "logs", workerLifecycleFlowRunIDPlaceholder}, RequiresRunID: true},
	{Name: "pull", Args: []string{"cloud", "pull", workerLifecycleFlowRunIDPlaceholder}, RequiresRunID: true},
	{Name: "cancel", Args: []string{"cloud", "cancel", workerLifecycleFlowRunIDPlaceholder}, RequiresRunID: true},
}

var workerLifecycleWorkflowFixtures = []workerLifecycleWorkflowFixture{
	{Name: "run", WorkflowKind: cloud.WorkflowKindRun, WorkflowCommand: "run"},
	{Name: "auto", WorkflowKind: cloud.WorkflowKindAuto, WorkflowCommand: "auto"},
	{Name: "review", WorkflowKind: cloud.WorkflowKindReview, WorkflowCommand: "review"},
}

func workerLifecycleFlowForWorkflow(workflowCommand string) []workerLifecycleFlowStep {
	steps := make([]workerLifecycleFlowStep, len(workerLifecycleSharedFlowSteps))
	for i, step := range workerLifecycleSharedFlowSteps {
		steps[i] = workerLifecycleFlowStep{
			Name:          step.Name,
			RequiresRunID: step.RequiresRunID,
			Args: workerLifecycleResolveArgs(step.Args, map[string]string{
				workerLifecycleFlowWorkflowPlaceholder: workflowCommand,
			}),
		}
	}
	return steps
}

func workerLifecycleResolveArgs(args []string, placeholders map[string]string) []string {
	resolved := make([]string, len(args))
	copy(resolved, args)

	for i, arg := range resolved {
		if replacement, ok := placeholders[arg]; ok && replacement != "" {
			resolved[i] = replacement
		}
	}
	return resolved
}

type workerLifecycleFlowRunInput struct {
	Step    workerLifecycleFlowStep
	RunID   string
	JSON    bool
	Stdin   io.Reader
	Stdout  io.Writer
	Context context.Context
}

type workerLifecycleFlowRunResult struct {
	Output string
	Err    error
}

// workerLifecycleFlowRunner dispatches lifecycle commands through testable
// run<Command> helpers (runHalRunCloud/runHalAutoCloud/runHalReviewCloud and
// runCloud<Subcommand> helpers), never through Cobra root execution.
type workerLifecycleFlowRunner struct {
	halDir  string
	baseDir string

	storeFactory        func() (cloud.Store, error)
	runConfigFactory    func() cloud.SubmitConfig
	autoConfigFactory   func() cloud.SubmitConfig
	reviewConfigFactory func() cloud.SubmitConfig
}

func newWorkerLifecycleFlowRunner(h *cloudLifecycleIntegrationHarness) *workerLifecycleFlowRunner {
	runner := &workerLifecycleFlowRunner{
		halDir:  h.HalDir,
		baseDir: h.WorkspaceDir,
		storeFactory: func() (cloud.Store, error) {
			return h.Store, nil
		},
		runConfigFactory:    runCloudConfigFactory,
		autoConfigFactory:   autoCloudConfigFactory,
		reviewConfigFactory: reviewCloudConfigFactory,
	}

	if runner.runConfigFactory == nil {
		runner.runConfigFactory = defaultCloudSubmitConfig
	}
	if runner.autoConfigFactory == nil {
		runner.autoConfigFactory = defaultCloudSubmitConfig
	}
	if runner.reviewConfigFactory == nil {
		runner.reviewConfigFactory = defaultCloudSubmitConfig
	}

	return runner
}

func (r *workerLifecycleFlowRunner) Run(input workerLifecycleFlowRunInput) workerLifecycleFlowRunResult {
	if input.Step.RequiresRunID && input.RunID == "" {
		return workerLifecycleFlowRunResult{Err: fmt.Errorf("step %q requires run ID", input.Step.Name)}
	}

	args := workerLifecycleResolveArgs(input.Step.Args, map[string]string{
		workerLifecycleFlowRunIDPlaceholder: input.RunID,
	})
	args = appendLifecycleJSONFlag(args, input.JSON)

	var capture bytes.Buffer
	stdout := io.Writer(&capture)
	if input.Stdout != nil {
		stdout = io.MultiWriter(&capture, input.Stdout)
	}

	stdin := input.Stdin
	if stdin == nil {
		stdin = defaultLifecycleStdin(lifecycleCommandName(args))
	}

	ctx := input.Context
	if ctx == nil {
		ctx = context.Background()
	}

	err := r.execute(args, stdin, stdout, ctx)
	return workerLifecycleFlowRunResult{
		Output: capture.String(),
		Err:    err,
	}
}

func (r *workerLifecycleFlowRunner) execute(args []string, in io.Reader, out io.Writer, ctx context.Context) error {
	if len(args) == 0 {
		return fmt.Errorf("command args must not be empty")
	}

	switch args[0] {
	case "run":
		flags, err := parseLifecycleWorkflowFlags("run", args[1:])
		if err != nil {
			return err
		}
		return runHalRunCloud(flags, r.halDir, r.baseDir, r.storeFactory, r.runConfigFactory, out)
	case "auto":
		flags, err := parseLifecycleWorkflowFlags("auto", args[1:])
		if err != nil {
			return err
		}
		return runHalAutoCloud(flags, r.halDir, r.baseDir, r.storeFactory, r.autoConfigFactory, out)
	case "review":
		flags, err := parseLifecycleWorkflowFlags("review", args[1:])
		if err != nil {
			return err
		}
		return runHalReviewCloud(flags, r.halDir, r.baseDir, r.storeFactory, r.reviewConfigFactory, out)
	case "cloud":
		return r.executeCloud(args, in, out, ctx)
	default:
		return fmt.Errorf("unsupported worker lifecycle command %q", args[0])
	}
}

func (r *workerLifecycleFlowRunner) executeCloud(args []string, in io.Reader, out io.Writer, ctx context.Context) error {
	if len(args) < 2 {
		return fmt.Errorf("cloud command requires a subcommand")
	}

	subcommand := args[1]
	subArgs := args[2:]

	switch subcommand {
	case "setup":
		profile, err := parseCloudSetupFlags(subArgs)
		if err != nil {
			return err
		}
		return runCloudSetup(r.halDir, profile, in, out)
	case "status":
		runID, jsonOutput, err := parseCloudRunIDFlags("status", subArgs)
		if err != nil {
			return err
		}
		return runCloudStatus(runID, jsonOutput, r.storeFactory, out)
	case "logs":
		runID, follow, jsonOutput, err := parseCloudLogsFlags(subArgs)
		if err != nil {
			return err
		}
		return runCloudLogs(runID, follow, jsonOutput, r.storeFactory, out, ctx)
	case "pull":
		runID, force, jsonOutput, artifacts, err := parseCloudPullFlags(subArgs)
		if err != nil {
			return err
		}
		return runCloudPull(runID, force, jsonOutput, artifacts, r.storeFactory, r.baseDir, out)
	case "cancel":
		runID, jsonOutput, err := parseCloudRunIDFlags("cancel", subArgs)
		if err != nil {
			return err
		}
		return runCloudCancel(runID, jsonOutput, r.storeFactory, out)
	default:
		return fmt.Errorf("unsupported cloud lifecycle subcommand %q", subcommand)
	}
}

func TestWorkerLifecycleFlowFixturesSharedAcrossWorkflows(t *testing.T) {
	if len(workerLifecycleSharedFlowSteps) == 0 {
		t.Fatal("workerLifecycleSharedFlowSteps must not be empty")
	}

	for _, fixture := range workerLifecycleWorkflowFixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			if !fixture.WorkflowKind.IsValid() {
				t.Fatalf("workflow kind %q must be valid", fixture.WorkflowKind)
			}

			steps := workerLifecycleFlowForWorkflow(fixture.WorkflowCommand)
			if len(steps) != len(workerLifecycleSharedFlowSteps) {
				t.Fatalf("flow length = %d, want %d", len(steps), len(workerLifecycleSharedFlowSteps))
			}

			for i, template := range workerLifecycleSharedFlowSteps {
				step := steps[i]
				if step.Name != template.Name {
					t.Fatalf("step %d name = %q, want %q", i, step.Name, template.Name)
				}
				if step.RequiresRunID != template.RequiresRunID {
					t.Fatalf("step %q RequiresRunID = %v, want %v", step.Name, step.RequiresRunID, template.RequiresRunID)
				}
				if slices.Contains(step.Args, workerLifecycleFlowWorkflowPlaceholder) {
					t.Fatalf("step %q still contains workflow placeholder: %v", step.Name, step.Args)
				}
			}

			submitStep := steps[1]
			if len(submitStep.Args) == 0 || submitStep.Args[0] != fixture.WorkflowCommand {
				t.Fatalf("submit step command = %v, want %q", submitStep.Args, fixture.WorkflowCommand)
			}
		})
	}
}

func TestWorkerLifecycleResolveArgs(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		placeholders map[string]string
		want         []string
	}{
		{
			name:         "replaces run id placeholder",
			args:         []string{"cloud", "status", workerLifecycleFlowRunIDPlaceholder},
			placeholders: map[string]string{workerLifecycleFlowRunIDPlaceholder: "run-123"},
			want:         []string{"cloud", "status", "run-123"},
		},
		{
			name:         "replaces workflow placeholder",
			args:         []string{workerLifecycleFlowWorkflowPlaceholder, "--cloud"},
			placeholders: map[string]string{workerLifecycleFlowWorkflowPlaceholder: "auto"},
			want:         []string{"auto", "--cloud"},
		},
		{
			name:         "missing value keeps placeholder",
			args:         []string{"cloud", "status", workerLifecycleFlowRunIDPlaceholder},
			placeholders: map[string]string{workerLifecycleFlowRunIDPlaceholder: ""},
			want:         []string{"cloud", "status", workerLifecycleFlowRunIDPlaceholder},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := append([]string(nil), tt.args...)
			got := workerLifecycleResolveArgs(tt.args, tt.placeholders)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("resolved args = %v, want %v", got, tt.want)
			}
			if !slices.Equal(tt.args, original) {
				t.Fatalf("original args mutated: got %v, want %v", tt.args, original)
			}
		})
	}
}

func TestWorkerLifecycleFlowRunner_DispatchesViaRunHelpers(t *testing.T) {
	for _, fixture := range workerLifecycleWorkflowFixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			h := setupCloudLifecycleIntegrationHarness(t)
			runner := newWorkerLifecycleFlowRunner(h)
			flow := workerLifecycleFlowForWorkflow(fixture.WorkflowCommand)

			setupResult := runner.Run(workerLifecycleFlowRunInput{Step: flow[0]})
			if setupResult.Err != nil {
				t.Fatalf("setup step failed: %v\noutput:\n%s", setupResult.Err, setupResult.Output)
			}

			submitResult := runner.Run(workerLifecycleFlowRunInput{Step: flow[1], JSON: true})
			if submitResult.Err != nil {
				t.Fatalf("submit step failed: %v\noutput:\n%s", submitResult.Err, submitResult.Output)
			}

			runPayload := mustDecodeWorkerLifecycleJSONOutput(t, submitResult.Output)
			runID, ok := lifecycleJSONStringField(runPayload, cloudLifecycleJSONKeyRunID)
			if !ok {
				t.Fatalf("submit output missing runId: %v", runPayload)
			}
			workflowKind, ok := lifecycleJSONStringField(runPayload, cloudLifecycleJSONKeyWorkflowKind)
			if !ok {
				t.Fatalf("submit output missing workflowKind: %v", runPayload)
			}
			if workflowKind != string(fixture.WorkflowKind) {
				t.Fatalf("workflowKind = %q, want %q", workflowKind, fixture.WorkflowKind)
			}

			statusResult := runner.Run(workerLifecycleFlowRunInput{Step: flow[2], RunID: runID, JSON: true})
			if statusResult.Err != nil {
				t.Fatalf("status step failed: %v\noutput:\n%s", statusResult.Err, statusResult.Output)
			}

			statusPayload := mustDecodeWorkerLifecycleJSONOutput(t, statusResult.Output)
			statusRunID, ok := lifecycleJSONStringField(statusPayload, cloudLifecycleJSONKeyRunID, "run_id")
			if !ok {
				t.Fatalf("status output missing run ID: %v", statusPayload)
			}
			if statusRunID != runID {
				t.Fatalf("status run ID = %q, want %q", statusRunID, runID)
			}
		})
	}
}

func TestWorkerLifecycleFlowRunner_RequiresRunIDForRunDependentSteps(t *testing.T) {
	h := setupCloudLifecycleIntegrationHarness(t)
	runner := newWorkerLifecycleFlowRunner(h)

	result := runner.Run(workerLifecycleFlowRunInput{Step: workerLifecycleSharedFlowSteps[2]})
	if result.Err == nil {
		t.Fatal("expected run-ID-required error, got nil")
	}
	if got, want := result.Err.Error(), `step "status" requires run ID`; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}
