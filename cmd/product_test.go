package cmd

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

func preserveProductPlanFlags(t *testing.T) {
	t.Helper()

	orig := productPlanEngineFlag
	t.Cleanup(func() {
		productPlanEngineFlag = orig
	})
}

func TestProductCommandIncludesPlanSubcommand(t *testing.T) {
	root := Root()
	product := findDirectSubcommandByName(root, "product")
	if product == nil {
		t.Fatal("product command should be registered on root")
	}

	plan := findDirectSubcommandByName(product, "plan")
	if plan == nil {
		t.Fatal("product plan subcommand should be registered")
	}
}

func TestRunProductPlanWithDeps_ForwardsEngineFromFallbackFlag(t *testing.T) {
	preserveProductPlanFlags(t)
	productPlanEngineFlag = "claude"

	called := false
	err := runProductPlanWithDeps(nil, nil, productPlanDeps{
		run: func(ctx context.Context, opts productPlanRunOptions) error {
			called = true
			if opts.Engine != "claude" {
				t.Fatalf("opts.Engine = %q, want %q", opts.Engine, "claude")
			}
			if opts.Dir != "." {
				t.Fatalf("opts.Dir = %q, want %q", opts.Dir, ".")
			}
			if opts.In == nil || opts.Out == nil || opts.ErrOut == nil {
				t.Fatal("expected stdio handles to be set")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runProductPlanWithDeps returned error: %v", err)
	}
	if !called {
		t.Fatal("deps.run was not called")
	}
}

func TestRunProductPlanWithDeps_ForwardsEngineFromCommandFlag(t *testing.T) {
	preserveProductPlanFlags(t)
	productPlanEngineFlag = "codex"

	cmd := &cobra.Command{Use: "plan"}
	cmd.Flags().String("engine", "codex", "Engine to use")
	if err := cmd.Flags().Set("engine", "pi"); err != nil {
		t.Fatalf("failed setting engine flag: %v", err)
	}

	called := false
	err := runProductPlanWithDeps(cmd, nil, productPlanDeps{
		run: func(ctx context.Context, opts productPlanRunOptions) error {
			called = true
			if opts.Engine != "pi" {
				t.Fatalf("opts.Engine = %q, want %q", opts.Engine, "pi")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runProductPlanWithDeps returned error: %v", err)
	}
	if !called {
		t.Fatal("deps.run was not called")
	}
}

func TestRunProductPlanWithDeps_EmptyEngineReturnsValidationExitCode(t *testing.T) {
	preserveProductPlanFlags(t)

	cmd := &cobra.Command{Use: "plan"}
	cmd.Flags().String("engine", "codex", "Engine to use")
	if err := cmd.Flags().Set("engine", ""); err != nil {
		t.Fatalf("failed setting engine flag: %v", err)
	}

	err := runProductPlanWithDeps(cmd, nil, productPlanDeps{
		run: func(ctx context.Context, opts productPlanRunOptions) error {
			t.Fatal("deps.run should not be called when engine resolution fails")
			return nil
		},
	})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}

	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) {
		t.Fatalf("error type = %T, want *ExitCodeError", err)
	}
	if exitErr.Code != ExitCodeValidation {
		t.Fatalf("exit code = %d, want %d", exitErr.Code, ExitCodeValidation)
	}
	if !strings.Contains(err.Error(), "--engine must not be empty") {
		t.Fatalf("error = %q, want engine-empty message", err.Error())
	}
}

func TestRunProductPlanFlowWithDeps_MissingHalDirReturnsActionableError(t *testing.T) {
	dir := t.TempDir()

	var out bytes.Buffer
	err := runProductPlanFlowWithDeps(
		context.Background(),
		productPlanRunOptions{
			Dir: dir,
			In:  strings.NewReader(""),
			Out: &out,
		},
		productPlanFlowDeps{},
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), ".hal/ not found - run 'hal init' first") {
		t.Fatalf("error = %q, want actionable init guidance", err.Error())
	}
}

func TestRunProductPlanFlowWithDeps_ExistingFilesPromptAndCancelWithoutWrites(t *testing.T) {
	dir := t.TempDir()
	productDir := filepath.Join(dir, template.HalDir, template.ProductDir)
	if err := os.MkdirAll(productDir, 0755); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", productDir, err)
	}

	missionPath := filepath.Join(productDir, template.ProductMissionFile)
	missionContent := "existing mission\n"
	if err := os.WriteFile(missionPath, []byte(missionContent), 0644); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", missionPath, err)
	}

	missionBefore, err := os.ReadFile(missionPath)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", missionPath, err)
	}

	var out bytes.Buffer
	err = runProductPlanFlowWithDeps(
		context.Background(),
		productPlanRunOptions{
			Dir: dir,
			In:  strings.NewReader("3\n"),
			Out: &out,
		},
		productPlanFlowDeps{},
	)
	if err != nil {
		t.Fatalf("runProductPlanFlowWithDeps returned error: %v", err)
	}

	output := out.String()
	for _, want := range []string{
		"Replace all files",
		"Update selected files",
		"Cancel",
		"Cancelled product planning. No files were changed.",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output %q does not contain %q", output, want)
		}
	}

	missionAfter, err := os.ReadFile(missionPath)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", missionPath, err)
	}
	if string(missionAfter) != string(missionBefore) {
		t.Fatalf("mission content changed on cancel: before=%q after=%q", string(missionBefore), string(missionAfter))
	}

	for _, name := range []string{template.ProductRoadmapFile, template.ProductTechStackFile} {
		path := filepath.Join(productDir, name)
		if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("expected %s to remain absent after cancel, stat error: %v", path, err)
		}
	}
}

func TestRunProductPlanFlowWithDeps_NoExistingFilesSkipsModePrompt(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, template.HalDir), 0755); err != nil {
		t.Fatalf("MkdirAll(.hal) error = %v", err)
	}

	var out bytes.Buffer
	err := runProductPlanFlowWithDeps(
		context.Background(),
		productPlanRunOptions{
			Dir: dir,
			In:  strings.NewReader(""),
			Out: &out,
		},
		productPlanFlowDeps{},
	)
	if err != nil {
		t.Fatalf("runProductPlanFlowWithDeps returned error: %v", err)
	}

	output := out.String()
	if strings.Contains(output, "Select an option [1/2/3]") {
		t.Fatalf("output should not prompt for mode when no product files exist, got %q", output)
	}
	if !strings.Contains(output, "Product planning preflight complete (replace_all).") {
		t.Fatalf("output %q missing completion line", output)
	}
}
