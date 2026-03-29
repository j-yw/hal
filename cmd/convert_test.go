package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/prd"
	"github.com/jywlabs/hal/internal/template"
)

type fakeConvertEngine struct {
	promptResponse string
	promptErr      error
}

func (fakeConvertEngine) Name() string { return "fake" }

func (fakeConvertEngine) Execute(ctx context.Context, prompt string, display *engine.Display) engine.Result {
	return engine.Result{}
}

func (f fakeConvertEngine) Prompt(ctx context.Context, prompt string) (string, error) {
	return f.promptResponse, f.promptErr
}

func (f fakeConvertEngine) StreamPrompt(ctx context.Context, prompt string, display *engine.Display) (string, error) {
	return f.promptResponse, f.promptErr
}

func preserveConvertFlags(t *testing.T) {
	t.Helper()
	origEngine := convertEngineFlag
	origOutput := convertOutputFlag
	origValidate := convertValidateFlag
	origArchive := convertArchiveFlag
	origForce := convertForceFlag
	origGranular := convertGranularFlag
	origBranch := convertBranchFlag
	origJSON := convertJSONFlag
	t.Cleanup(func() {
		convertEngineFlag = origEngine
		convertOutputFlag = origOutput
		convertValidateFlag = origValidate
		convertArchiveFlag = origArchive
		convertForceFlag = origForce
		convertGranularFlag = origGranular
		convertBranchFlag = origBranch
		convertJSONFlag = origJSON
	})
}

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()

	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}

	os.Stdout = w
	runErr := fn()

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close stdout writer: %v", err)
	}
	os.Stdout = origStdout

	output, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("failed to read captured stdout: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("failed to close stdout reader: %v", err)
	}

	return string(output), runErr
}

func TestConvertUsageIncludesSafetyAndBranchFlags(t *testing.T) {
	usage := convertCmd.UsageString()
	checks := []string{
		"--archive",
		"--force",
		"--granular",
		"--branch",
		"Archive existing feature state before writing canonical .hal/prd.json",
		"Allow canonical overwrite without archive when branch mismatch protection would block",
		"Decompose into 8-15 atomic tasks (T-XXX IDs) for autonomous execution",
		"Pin generated branchName (overrides markdown-derived branch)",
	}

	for _, want := range checks {
		if !strings.Contains(usage, want) {
			t.Fatalf("convert usage missing %q:\n%s", want, usage)
		}
	}
}

func TestConvertLongHelpDocumentsSourceSelectionAndSafety(t *testing.T) {
	help := convertCmd.Long

	checks := []string{
		"Default convert does NOT archive existing state.",
		"--archive is only supported when output is canonical .hal/prd.json.",
		"scans .hal/prd-*.md and picks newest by modified time",
		"picks lexicographically ascending filename",
		"Using source: <path>",
		"use --archive or --force to override",
	}

	for _, want := range checks {
		if !strings.Contains(help, want) {
			t.Fatalf("convert long help missing %q:\n%s", want, help)
		}
	}
}

func TestRunConvertWithDeps_DefaultSafetyFlagsAreFalse(t *testing.T) {
	preserveConvertFlags(t)

	tmpDir := t.TempDir()
	mdPath := filepath.Join(tmpDir, "prd.md")
	if err := os.WriteFile(mdPath, []byte("# PRD"), 0644); err != nil {
		t.Fatalf("failed to write markdown fixture: %v", err)
	}

	convertEngineFlag = "claude"
	convertOutputFlag = filepath.Join(tmpDir, "out.json")
	convertValidateFlag = false
	convertArchiveFlag = false
	convertForceFlag = false
	convertGranularFlag = false
	convertBranchFlag = ""

	called := false
	deps := convertDeps{
		newEngine: func(name string) (engine.Engine, error) {
			if name != "claude" {
				t.Fatalf("newEngine called with %q, want %q", name, "claude")
			}
			return fakeConvertEngine{}, nil
		},
		convertWithEngine: func(ctx context.Context, eng engine.Engine, gotMDPath, gotOutPath string, opts prd.ConvertOptions, display *engine.Display) error {
			called = true
			if gotMDPath != mdPath {
				t.Fatalf("mdPath = %q, want %q", gotMDPath, mdPath)
			}
			if gotOutPath != convertOutputFlag {
				t.Fatalf("outPath = %q, want %q", gotOutPath, convertOutputFlag)
			}
			if opts.Archive {
				t.Fatal("opts.Archive = true, want false")
			}
			if opts.Force {
				t.Fatal("opts.Force = true, want false")
			}
			if opts.Granular {
				t.Fatal("opts.Granular = true, want false")
			}
			if opts.BranchName != "" {
				t.Fatalf("opts.BranchName = %q, want empty", opts.BranchName)
			}
			if display == nil {
				t.Fatal("display should not be nil")
			}
			return nil
		},
		validateWithEngine: func(ctx context.Context, eng engine.Engine, prdPath string, display *engine.Display) (*prd.ValidationResult, error) {
			t.Fatal("validateWithEngine should not be called when --validate is false")
			return nil, nil
		},
	}

	if err := runConvertWithDeps(nil, []string{mdPath}, deps); err != nil {
		t.Fatalf("runConvertWithDeps returned error: %v", err)
	}
	if !called {
		t.Fatal("convertWithEngine was not called")
	}
}

func TestRunConvertWithDeps_ArchiveCustomOutputReturnsError(t *testing.T) {
	preserveConvertFlags(t)

	tmpDir := t.TempDir()
	mdPath := filepath.Join(tmpDir, "prd.md")
	if err := os.WriteFile(mdPath, []byte("# PRD"), 0644); err != nil {
		t.Fatalf("failed to write markdown fixture: %v", err)
	}

	convertEngineFlag = "claude"
	convertOutputFlag = filepath.Join(tmpDir, "custom-prd.json")
	convertValidateFlag = false
	convertArchiveFlag = true
	convertForceFlag = false
	convertGranularFlag = false
	convertBranchFlag = ""

	deps := convertDeps{
		newEngine: func(name string) (engine.Engine, error) {
			return fakeConvertEngine{}, nil
		},
		convertWithEngine: func(ctx context.Context, eng engine.Engine, gotMDPath, gotOutPath string, opts prd.ConvertOptions, display *engine.Display) error {
			if !opts.Archive {
				t.Fatal("opts.Archive should be true")
			}
			return fmt.Errorf("--archive is only supported when output is .hal/prd.json")
		},
		validateWithEngine: func(ctx context.Context, eng engine.Engine, prdPath string, display *engine.Display) (*prd.ValidationResult, error) {
			return nil, nil
		},
	}

	err := runConvertWithDeps(nil, []string{mdPath}, deps)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "--archive is only supported when output is .hal/prd.json") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunConvertWithDeps_FlagWiring(t *testing.T) {
	tests := []struct {
		name       string
		outputFlag string
		archive    bool
		force      bool
		granular   bool
		branch     string
		wantOut    string
	}{
		{
			name:       "explicit output passes all convert options",
			outputFlag: "custom-prd.json",
			archive:    true,
			force:      true,
			granular:   true,
			branch:     "hal/pinned-feature",
			wantOut:    "custom-prd.json",
		},
		{
			name:       "empty output flag uses canonical default",
			outputFlag: "",
			archive:    false,
			force:      false,
			granular:   false,
			branch:     "",
			wantOut:    filepath.Join(template.HalDir, template.PRDFile),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			preserveConvertFlags(t)

			tmpDir := t.TempDir()
			mdPath := filepath.Join(tmpDir, "prd.md")
			if err := os.WriteFile(mdPath, []byte("# PRD"), 0644); err != nil {
				t.Fatalf("failed to write markdown fixture: %v", err)
			}

			outputFlag := tt.outputFlag
			wantOut := tt.wantOut
			if outputFlag != "" {
				outputFlag = filepath.Join(tmpDir, outputFlag)
				wantOut = filepath.Join(tmpDir, wantOut)
			}

			convertEngineFlag = "claude"
			convertOutputFlag = outputFlag
			convertValidateFlag = false
			convertArchiveFlag = tt.archive
			convertForceFlag = tt.force
			convertGranularFlag = tt.granular
			convertBranchFlag = tt.branch

			called := false
			deps := convertDeps{
				newEngine: func(name string) (engine.Engine, error) {
					if name != "claude" {
						t.Fatalf("newEngine called with %q, want %q", name, "claude")
					}
					return fakeConvertEngine{}, nil
				},
				convertWithEngine: func(ctx context.Context, eng engine.Engine, gotMDPath, gotOutPath string, opts prd.ConvertOptions, display *engine.Display) error {
					called = true
					if gotMDPath != mdPath {
						t.Fatalf("mdPath = %q, want %q", gotMDPath, mdPath)
					}
					if gotOutPath != wantOut {
						t.Fatalf("outPath = %q, want %q", gotOutPath, wantOut)
					}
					if opts.Archive != tt.archive {
						t.Fatalf("opts.Archive = %v, want %v", opts.Archive, tt.archive)
					}
					if opts.Force != tt.force {
						t.Fatalf("opts.Force = %v, want %v", opts.Force, tt.force)
					}
					if opts.Granular != tt.granular {
						t.Fatalf("opts.Granular = %v, want %v", opts.Granular, tt.granular)
					}
					if opts.BranchName != tt.branch {
						t.Fatalf("opts.BranchName = %q, want %q", opts.BranchName, tt.branch)
					}
					if display == nil {
						t.Fatal("display should not be nil")
					}
					return nil
				},
				validateWithEngine: func(ctx context.Context, eng engine.Engine, prdPath string, display *engine.Display) (*prd.ValidationResult, error) {
					t.Fatal("validateWithEngine should not be called when --validate is false")
					return nil, nil
				},
			}

			if err := runConvertWithDeps(nil, []string{mdPath}, deps); err != nil {
				t.Fatalf("runConvertWithDeps returned error: %v", err)
			}
			if !called {
				t.Fatal("convertWithEngine was not called")
			}
		})
	}
}

func TestRunConvertWithDeps_PrintsSelectedSourceMessage(t *testing.T) {
	preserveConvertFlags(t)

	tmpDir := t.TempDir()
	mdPath := filepath.Join(tmpDir, "prd.md")
	if err := os.WriteFile(mdPath, []byte("# PRD"), 0644); err != nil {
		t.Fatalf("failed to write markdown fixture: %v", err)
	}
	outPath := filepath.Join(tmpDir, "out.json")

	convertEngineFlag = "claude"
	convertOutputFlag = outPath
	convertValidateFlag = false
	convertArchiveFlag = false
	convertForceFlag = false
	convertGranularFlag = false
	convertBranchFlag = ""

	deps := convertDeps{
		newEngine: func(name string) (engine.Engine, error) {
			return fakeConvertEngine{
				promptResponse: `{"project":"test","branchName":"hal/new","description":"desc","userStories":[]}`,
			}, nil
		},
		convertWithEngine: prd.ConvertWithEngine,
		validateWithEngine: func(ctx context.Context, eng engine.Engine, prdPath string, display *engine.Display) (*prd.ValidationResult, error) {
			return nil, nil
		},
	}

	output, err := captureStdout(t, func() error {
		return runConvertWithDeps(nil, []string{mdPath}, deps)
	})
	if err != nil {
		t.Fatalf("runConvertWithDeps returned error: %v", err)
	}
	if !strings.Contains(output, "Using source: "+mdPath) {
		t.Fatalf("expected selected-source message in output, got %q", output)
	}
}

func TestRunConvertWithDeps_ExplicitSourceMustExist(t *testing.T) {
	preserveConvertFlags(t)

	tmpDir := t.TempDir()
	mdPath := filepath.Join(tmpDir, "missing-prd.md")

	convertEngineFlag = "claude"
	convertOutputFlag = filepath.Join(tmpDir, "out.json")
	convertValidateFlag = false
	convertArchiveFlag = false
	convertForceFlag = false
	convertGranularFlag = false
	convertBranchFlag = ""

	newEngineCalled := false
	convertCalled := false
	deps := convertDeps{
		newEngine: func(name string) (engine.Engine, error) {
			newEngineCalled = true
			return fakeConvertEngine{}, nil
		},
		convertWithEngine: func(ctx context.Context, eng engine.Engine, gotMDPath, gotOutPath string, opts prd.ConvertOptions, display *engine.Display) error {
			convertCalled = true
			return nil
		},
		validateWithEngine: func(ctx context.Context, eng engine.Engine, prdPath string, display *engine.Display) (*prd.ValidationResult, error) {
			return nil, nil
		},
	}

	err := runConvertWithDeps(nil, []string{mdPath}, deps)
	if err == nil {
		t.Fatal("expected an error for missing markdown source")
	}
	if !strings.Contains(err.Error(), "markdown PRD not found: "+mdPath) {
		t.Fatalf("unexpected error: %v", err)
	}
	if newEngineCalled {
		t.Fatal("newEngine should not be called when markdown source is missing")
	}
	if convertCalled {
		t.Fatal("convertWithEngine should not be called when markdown source is missing")
	}
}
