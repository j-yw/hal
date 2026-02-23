package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/prd"
)

type fakeConvertEngine struct{}

func (fakeConvertEngine) Name() string { return "fake" }

func (fakeConvertEngine) Execute(ctx context.Context, prompt string, display *engine.Display) engine.Result {
	return engine.Result{}
}

func (fakeConvertEngine) Prompt(ctx context.Context, prompt string) (string, error) {
	return "", nil
}

func (fakeConvertEngine) StreamPrompt(ctx context.Context, prompt string, display *engine.Display) (string, error) {
	return "", nil
}

func preserveConvertFlags(t *testing.T) {
	t.Helper()
	origEngine := convertEngineFlag
	origOutput := convertOutputFlag
	origValidate := convertValidateFlag
	origArchive := convertArchiveFlag
	origForce := convertForceFlag
	t.Cleanup(func() {
		convertEngineFlag = origEngine
		convertOutputFlag = origOutput
		convertValidateFlag = origValidate
		convertArchiveFlag = origArchive
		convertForceFlag = origForce
	})
}

func TestConvertUsageIncludesSafetyFlags(t *testing.T) {
	usage := convertCmd.UsageString()
	if !strings.Contains(usage, "--archive") {
		t.Fatalf("convert usage missing --archive flag:\n%s", usage)
	}
	if !strings.Contains(usage, "--force") {
		t.Fatalf("convert usage missing --force flag:\n%s", usage)
	}
	if !strings.Contains(usage, "Archive existing feature state before writing canonical .hal/prd.json") {
		t.Fatalf("convert usage missing --archive help text:\n%s", usage)
	}
	if !strings.Contains(usage, "Allow canonical overwrite without archive when branch mismatch protection would block") {
		t.Fatalf("convert usage missing --force help text:\n%s", usage)
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

func TestRunConvertWithDeps_ExplicitSourceMustExist(t *testing.T) {
	preserveConvertFlags(t)

	tmpDir := t.TempDir()
	mdPath := filepath.Join(tmpDir, "missing-prd.md")

	convertEngineFlag = "claude"
	convertOutputFlag = filepath.Join(tmpDir, "out.json")
	convertValidateFlag = false
	convertArchiveFlag = false
	convertForceFlag = false

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
