package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/prd"
	"github.com/spf13/cobra"
)

type planFakeEngine struct{}

func (planFakeEngine) Name() string { return "fake" }
func (planFakeEngine) Execute(context.Context, string, *engine.Display) engine.Result {
	return engine.Result{}
}
func (planFakeEngine) Prompt(context.Context, string) (string, error) { return "", nil }
func (planFakeEngine) StreamPrompt(context.Context, string, *engine.Display) (string, error) {
	return "", nil
}

func writePlanInputFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func newPlanTestCommand(t *testing.T, in io.Reader, out *bytes.Buffer) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "plan"}
	cmd.Flags().StringP("engine", "e", "codex", "")
	cmd.Flags().StringP("format", "f", "markdown", "")
	cmd.Flags().String("input", "", "")
	cmd.Flags().Bool("no-questions", false, "")
	cmd.Flags().Bool("json", false, "")
	cmd.SetIn(in)
	cmd.SetOut(out)
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Flags().Set("engine", "fake"); err != nil {
		t.Fatalf("set engine: %v", err)
	}
	return cmd
}

func requirePlanJSON(t *testing.T, out *bytes.Buffer) PlanResult {
	t.Helper()
	var result PlanResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not pure JSON: %v\n%s", err, out.String())
	}
	return result
}

func requirePlanExitCode(t *testing.T, err error, code int) {
	t.Helper()
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) {
		t.Fatalf("error = %T %v, want ExitCodeError", err, err)
	}
	if exitErr.Code != code {
		t.Fatalf("exit code = %d, want %d", exitErr.Code, code)
	}
}

func TestRunPlanWithDeps_JSONInputFilePureOutput(t *testing.T) {
	tmp := t.TempDir()
	inputPath := filepath.Join(tmp, "feature.md")
	writePlanInputFile(t, inputPath, "Build a dashboard for usage metrics.\n")

	var out bytes.Buffer
	cmd := newPlanTestCommand(t, strings.NewReader(""), &out)
	for name, value := range map[string]string{
		"input":  inputPath,
		"format": "json",
		"json":   "true",
	} {
		if err := cmd.Flags().Set(name, value); err != nil {
			t.Fatalf("set %s: %v", name, err)
		}
	}
	if err := cmd.Flags().Set("no-questions", "true"); err != nil {
		t.Fatalf("set no-questions: %v", err)
	}

	var gotDescription string
	var gotOpts prd.GenerateOptions
	var gotDisplay *engine.Display
	err := runPlanWithDeps(cmd, nil, planDeps{
		newEngine: func(name string) (engine.Engine, error) {
			if name != "fake" {
				t.Fatalf("engine name = %q, want fake", name)
			}
			return planFakeEngine{}, nil
		},
		generateWithEngineOptions: func(ctx context.Context, eng engine.Engine, description string, opts prd.GenerateOptions, display *engine.Display) (string, error) {
			gotDescription = description
			gotOpts = opts
			gotDisplay = display
			return ".hal/prd.json", nil
		},
	})
	if err != nil {
		t.Fatalf("runPlanWithDeps error: %v", err)
	}
	if gotDescription != "Build a dashboard for usage metrics." {
		t.Fatalf("description = %q", gotDescription)
	}
	if gotOpts.Format != "json" || gotOpts.AskQuestions {
		t.Fatalf("GenerateOptions = %+v, want format=json askQuestions=false", gotOpts)
	}
	if gotDisplay != nil {
		t.Fatal("display should be nil in --json mode so stdout remains pure JSON")
	}

	result := requirePlanJSON(t, &out)
	if result.ContractVersion != PlanContractVersion {
		t.Fatalf("contractVersion = %d, want %d", result.ContractVersion, PlanContractVersion)
	}
	if !result.OK || result.OutputPath != ".hal/prd.json" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.InputSource != PlanInputSourceFile {
		t.Fatalf("inputSource = %q, want %q", result.InputSource, PlanInputSourceFile)
	}
	if result.QuestionsAsked {
		t.Fatal("questionsAsked should be false with --no-questions")
	}
}

func TestRunPlanWithDeps_JSONPositionalInputSource(t *testing.T) {
	var out bytes.Buffer
	cmd := newPlanTestCommand(t, strings.NewReader(""), &out)
	for name, value := range map[string]string{
		"format": "markdown",
		"json":   "true",
	} {
		if err := cmd.Flags().Set(name, value); err != nil {
			t.Fatalf("set %s: %v", name, err)
		}
	}
	if err := cmd.Flags().Set("no-questions", "true"); err != nil {
		t.Fatalf("set no-questions: %v", err)
	}

	err := runPlanWithDeps(cmd, []string{"add", "search"}, planDeps{
		newEngine: func(string) (engine.Engine, error) { return planFakeEngine{}, nil },
		generateWithEngineOptions: func(ctx context.Context, eng engine.Engine, description string, opts prd.GenerateOptions, display *engine.Display) (string, error) {
			if description != "add search" {
				t.Fatalf("description = %q, want add search", description)
			}
			return ".hal/prd-add-search.md", nil
		},
	})
	if err != nil {
		t.Fatalf("runPlanWithDeps error: %v", err)
	}

	result := requirePlanJSON(t, &out)
	if result.InputSource != PlanInputSourceArgument {
		t.Fatalf("inputSource = %q, want %q", result.InputSource, PlanInputSourceArgument)
	}
	if result.Format != "markdown" {
		t.Fatalf("format = %q, want markdown", result.Format)
	}
	if len(result.NextSteps) == 0 || !strings.Contains(result.NextSteps[0], "hal convert .hal/prd-add-search.md --json") {
		t.Fatalf("nextSteps = %#v", result.NextSteps)
	}
}

func TestRunPlanWithDeps_JSONStdinInputSource(t *testing.T) {
	var out bytes.Buffer
	cmd := newPlanTestCommand(t, strings.NewReader("Plan from stdin"), &out)
	for name, value := range map[string]string{
		"input": "-",
		"json":  "true",
	} {
		if err := cmd.Flags().Set(name, value); err != nil {
			t.Fatalf("set %s: %v", name, err)
		}
	}
	if err := cmd.Flags().Set("no-questions", "true"); err != nil {
		t.Fatalf("set no-questions: %v", err)
	}

	err := runPlanWithDeps(cmd, nil, planDeps{
		newEngine: func(string) (engine.Engine, error) { return planFakeEngine{}, nil },
		generateWithEngineOptions: func(ctx context.Context, eng engine.Engine, description string, opts prd.GenerateOptions, display *engine.Display) (string, error) {
			if description != "Plan from stdin" {
				t.Fatalf("description = %q, want stdin content", description)
			}
			return ".hal/prd-plan-from-stdin.md", nil
		},
	})
	if err != nil {
		t.Fatalf("runPlanWithDeps error: %v", err)
	}

	result := requirePlanJSON(t, &out)
	if result.InputSource != PlanInputSourceStdin {
		t.Fatalf("inputSource = %q, want %q", result.InputSource, PlanInputSourceStdin)
	}
}

func TestRunPlanWithDeps_HumanEditorFallbackWhenTTY(t *testing.T) {
	var out bytes.Buffer
	cmd := newPlanTestCommand(t, strings.NewReader(""), &out)

	openEditorCalled := false
	var gotOpts prd.GenerateOptions
	err := runPlanWithDeps(cmd, nil, planDeps{
		isTTY: func(io.Reader) bool { return true },
		openEditor: func(in io.Reader, out io.Writer, errOut io.Writer) (string, error) {
			openEditorCalled = true
			return "editor feature brief", nil
		},
		newEngine: func(string) (engine.Engine, error) { return planFakeEngine{}, nil },
		generateWithEngineOptions: func(ctx context.Context, eng engine.Engine, description string, opts prd.GenerateOptions, display *engine.Display) (string, error) {
			if description != "editor feature brief" {
				t.Fatalf("description = %q, want editor content", description)
			}
			gotOpts = opts
			return ".hal/prd-editor-feature-brief.md", nil
		},
	})
	if err != nil {
		t.Fatalf("runPlanWithDeps error: %v", err)
	}
	if !openEditorCalled {
		t.Fatal("editor should be opened for TTY human mode without explicit input")
	}
	if !gotOpts.AskQuestions {
		t.Fatal("editor human flow should ask questions by default")
	}
}

func TestRunPlanWithDeps_NonTTYNoInputDoesNotOpenEditor(t *testing.T) {
	var out bytes.Buffer
	cmd := newPlanTestCommand(t, strings.NewReader(""), &out)

	engineCalled := false
	openEditorCalled := false
	err := runPlanWithDeps(cmd, nil, planDeps{
		openEditor: func(in io.Reader, out io.Writer, errOut io.Writer) (string, error) {
			openEditorCalled = true
			return "", nil
		},
		newEngine: func(string) (engine.Engine, error) {
			engineCalled = true
			return planFakeEngine{}, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "pass feature-description, --input <path>, or --input -") {
		t.Fatalf("error = %v, want input guidance", err)
	}
	if engineCalled || openEditorCalled {
		t.Fatalf("engineCalled=%v openEditorCalled=%v, both should be false", engineCalled, openEditorCalled)
	}
}

func TestRunPlanWithDeps_ValidationFailuresDoNotCallEngine(t *testing.T) {
	tmp := t.TempDir()
	inputPath := filepath.Join(tmp, "feature.md")
	writePlanInputFile(t, inputPath, "Build search.\n")
	dirPath := filepath.Join(tmp, "input-dir")
	if err := os.Mkdir(dirPath, 0755); err != nil {
		t.Fatal(err)
	}
	emptyPath := filepath.Join(tmp, "empty.md")
	writePlanInputFile(t, emptyPath, "\n")
	missingPath := filepath.Join(tmp, "missing.md")

	tests := []struct {
		name        string
		args        []string
		flags       map[string]string
		stdin       string
		wantErr     string
		wantJSON    bool
		wantCode    int
		wantSource  string
		wantSummary string
	}{
		{
			name:       "input stdin requires no questions",
			flags:      map[string]string{"input": "-"},
			stdin:      "Plan from stdin",
			wantErr:    "--input - requires --no-questions",
			wantCode:   ExitCodeValidation,
			wantSource: PlanInputSourceStdin,
		},
		{
			name:       "json requires no questions",
			flags:      map[string]string{"input": inputPath, "json": "true"},
			wantErr:    "--json requires --no-questions",
			wantJSON:   true,
			wantCode:   ExitCodeValidation,
			wantSource: PlanInputSourceFile,
		},
		{
			name:       "json requires explicit input",
			flags:      map[string]string{"json": "true", "no-questions": "true"},
			wantErr:    "--json requires explicit input",
			wantJSON:   true,
			wantCode:   ExitCodeValidation,
			wantSource: PlanInputSourceEditor,
		},
		{
			name:       "invalid format before engine",
			flags:      map[string]string{"input": inputPath, "format": "xml", "json": "true", "no-questions": "true"},
			wantErr:    "invalid format",
			wantJSON:   true,
			wantCode:   ExitCodeValidation,
			wantSource: PlanInputSourceFile,
		},
		{
			name:       "input and positional conflict",
			args:       []string{"add search"},
			flags:      map[string]string{"input": inputPath},
			wantErr:    "use either --input or positional feature-description",
			wantCode:   ExitCodeValidation,
			wantSource: PlanInputSourceFile,
		},
		{
			name:       "empty stdin",
			flags:      map[string]string{"input": "-", "no-questions": "true"},
			stdin:      "\n",
			wantErr:    "no description provided from stdin",
			wantCode:   ExitCodeValidation,
			wantSource: PlanInputSourceStdin,
		},
		{
			name:       "missing file",
			flags:      map[string]string{"input": missingPath, "no-questions": "true"},
			wantErr:    "failed to read input file",
			wantCode:   ExitCodeValidation,
			wantSource: PlanInputSourceFile,
		},
		{
			name:       "directory input",
			flags:      map[string]string{"input": dirPath, "no-questions": "true"},
			wantErr:    "failed to read input file",
			wantCode:   ExitCodeValidation,
			wantSource: PlanInputSourceFile,
		},
		{
			name:       "empty file",
			flags:      map[string]string{"input": emptyPath, "no-questions": "true"},
			wantErr:    "no description provided in",
			wantCode:   ExitCodeValidation,
			wantSource: PlanInputSourceFile,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			cmd := newPlanTestCommand(t, strings.NewReader(tt.stdin), &out)
			for name, value := range tt.flags {
				if err := cmd.Flags().Set(name, value); err != nil {
					t.Fatalf("set %s: %v", name, err)
				}
			}

			engineCalled := false
			err := runPlanWithDeps(cmd, tt.args, planDeps{
				newEngine: func(string) (engine.Engine, error) {
					engineCalled = true
					return planFakeEngine{}, nil
				},
			})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
			requirePlanExitCode(t, err, tt.wantCode)
			if engineCalled {
				t.Fatal("engine should not be created after validation failure")
			}
			if tt.wantJSON {
				result := requirePlanJSON(t, &out)
				if result.OK {
					t.Fatal("OK should be false for validation failure")
				}
				if result.QuestionsAsked {
					t.Fatal("questionsAsked should be false for validation failure because no questions were asked")
				}
				if result.InputSource != tt.wantSource {
					t.Fatalf("inputSource = %q, want %q", result.InputSource, tt.wantSource)
				}
				if !strings.Contains(result.Error, tt.wantErr) {
					t.Fatalf("JSON error = %q, want containing %q", result.Error, tt.wantErr)
				}
				if result.Summary != "Invalid plan input" {
					t.Fatalf("summary = %q, want Invalid plan input", result.Summary)
				}
			} else if out.Len() != 0 {
				t.Fatalf("stdout = %q, want empty outside --json validation failure", out.String())
			}
		})
	}
}

func TestRunPlanWithDeps_UnreadableInputFileDoesNotCallEngine(t *testing.T) {
	var out bytes.Buffer
	cmd := newPlanTestCommand(t, strings.NewReader(""), &out)
	if err := cmd.Flags().Set("input", "secret.md"); err != nil {
		t.Fatalf("set input: %v", err)
	}
	if err := cmd.Flags().Set("no-questions", "true"); err != nil {
		t.Fatalf("set no-questions: %v", err)
	}

	engineCalled := false
	err := runPlanWithDeps(cmd, nil, planDeps{
		readFile: func(string) ([]byte, error) {
			return nil, os.ErrPermission
		},
		newEngine: func(string) (engine.Engine, error) {
			engineCalled = true
			return planFakeEngine{}, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "failed to read input file secret.md") {
		t.Fatalf("error = %v, want unreadable input error", err)
	}
	if engineCalled {
		t.Fatal("engine should not be created after unreadable input")
	}
	if out.Len() != 0 {
		t.Fatalf("stdout = %q, want empty outside --json validation failure", out.String())
	}
}

func TestRunPlanWithDeps_JSONFailureResult(t *testing.T) {
	tmp := t.TempDir()
	inputPath := filepath.Join(tmp, "feature.md")
	writePlanInputFile(t, inputPath, "Build search.\n")

	var out bytes.Buffer
	cmd := newPlanTestCommand(t, strings.NewReader(""), &out)
	for name, value := range map[string]string{
		"input": inputPath,
		"json":  "true",
	} {
		if err := cmd.Flags().Set(name, value); err != nil {
			t.Fatalf("set %s: %v", name, err)
		}
	}
	if err := cmd.Flags().Set("no-questions", "true"); err != nil {
		t.Fatalf("set no-questions: %v", err)
	}

	err := runPlanWithDeps(cmd, nil, planDeps{
		newEngine: func(string) (engine.Engine, error) { return planFakeEngine{}, nil },
		generateWithEngineOptions: func(ctx context.Context, eng engine.Engine, description string, opts prd.GenerateOptions, display *engine.Display) (string, error) {
			return "", errors.New("engine unavailable")
		},
	})
	if err == nil || !strings.Contains(err.Error(), "engine unavailable") {
		t.Fatalf("runPlanWithDeps error = %v, want engine unavailable", err)
	}
	requirePlanExitCode(t, err, ExitCodeExpectedNonZero)
	result := requirePlanJSON(t, &out)
	if result.OK {
		t.Fatal("OK should be false for generation failure")
	}
	if result.Error == "" || !strings.Contains(result.Error, "engine unavailable") {
		t.Fatalf("error = %q, want engine unavailable", result.Error)
	}
	if result.OutputPath != "" {
		t.Fatalf("outputPath = %q, want empty on failure", result.OutputPath)
	}
}

func TestPlanInputSourceConstants(t *testing.T) {
	got := []string{PlanInputSourceArgument, PlanInputSourceFile, PlanInputSourceStdin, PlanInputSourceEditor}
	want := []string{"argument", "file", "stdin", "editor"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("input source constants = %#v, want %#v", got, want)
		}
	}
}
