package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"

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
