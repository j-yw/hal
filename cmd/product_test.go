package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/product"
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

func TestParseProductPlanTargets_ConciseInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  product.SelectedTargets
	}{
		{
			name:  "single shorthand",
			input: "m",
			want:  product.SelectedTargets{Mission: true},
		},
		{
			name:  "combined shorthand",
			input: "rt",
			want:  product.SelectedTargets{Roadmap: true, TechStack: true},
		},
		{
			name:  "comma separated shorthand",
			input: "m,r,t",
			want:  product.SelectedTargets{Mission: true, Roadmap: true, TechStack: true},
		},
		{
			name:  "word tokens",
			input: "mission roadmap",
			want:  product.SelectedTargets{Mission: true, Roadmap: true},
		},
		{
			name:  "numeric tokens",
			input: "2 3",
			want:  product.SelectedTargets{Roadmap: true, TechStack: true},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseProductPlanTargets(tc.input)
			if err != nil {
				t.Fatalf("parseProductPlanTargets(%q) error = %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("parseProductPlanTargets(%q) = %+v, want %+v", tc.input, got, tc.want)
			}
		})
	}
}

func TestParseProductPlanTargets_InvalidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:    "empty",
			input:   "",
			wantErr: "product target selection is required",
		},
		{
			name:    "invalid token",
			input:   "x",
			wantErr: "invalid product target selection \"x\" (use mission/roadmap/tech-stack or m/r/t)",
		},
		{
			name:    "partially invalid",
			input:   "m,x",
			wantErr: "invalid product target selection \"x\" (use mission/roadmap/tech-stack or m/r/t)",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := parseProductPlanTargets(tc.input)
			if err == nil {
				t.Fatalf("parseProductPlanTargets(%q) error = nil, want %q", tc.input, tc.wantErr)
			}
			if err.Error() != tc.wantErr {
				t.Fatalf("parseProductPlanTargets(%q) error = %q, want %q", tc.input, err.Error(), tc.wantErr)
			}
		})
	}
}

func TestRunProductPlanFlowWithDeps_UpdateSelectedPassesTargetsToStages(t *testing.T) {
	dir := t.TempDir()
	productDir := filepath.Join(dir, template.HalDir, template.ProductDir)
	if err := os.MkdirAll(productDir, 0755); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", productDir, err)
	}
	if err := os.WriteFile(filepath.Join(productDir, template.ProductMissionFile), []byte("existing\n"), 0644); err != nil {
		t.Fatalf("WriteFile(mission) error = %v", err)
	}

	selected := product.SelectedTargets{Mission: true, TechStack: true}
	wantAnswers := product.CollectedAnswers{
		Mission: []product.InterviewAnswer{
			{Question: "q", Answer: "a"},
		},
	}

	collectCalled := false
	generateCalled := false
	var out bytes.Buffer
	err := runProductPlanFlowWithDeps(
		context.Background(),
		productPlanRunOptions{
			Dir:    dir,
			Engine: "codex",
			In:     strings.NewReader(""),
			Out:    &out,
		},
		productPlanFlowDeps{
			selectMode: func(in io.Reader, out io.Writer) (productPlanMode, error) {
				_ = in
				_ = out
				return productPlanModeUpdateSelected, nil
			},
			selectTargets: func(in io.Reader, out io.Writer) (product.SelectedTargets, error) {
				_ = in
				_ = out
				return selected, nil
			},
			collectAnswers: func(in io.Reader, out io.Writer, targets product.SelectedTargets) (product.CollectedAnswers, error) {
				_ = in
				_ = out
				collectCalled = true
				if targets != selected {
					t.Fatalf("collect targets = %+v, want %+v", targets, selected)
				}
				return wantAnswers, nil
			},
			generatePayload: func(ctx context.Context, input productPlanGenerateInput) (product.GeneratedPayload, error) {
				_ = ctx
				generateCalled = true
				if input.Engine != "codex" {
					t.Fatalf("generate engine = %q, want %q", input.Engine, "codex")
				}
				if input.Targets != selected {
					t.Fatalf("generate targets = %+v, want %+v", input.Targets, selected)
				}
				if !reflect.DeepEqual(input.Answers, wantAnswers) {
					t.Fatalf("generate answers = %+v, want %+v", input.Answers, wantAnswers)
				}
				return product.GeneratedPayload{}, nil
			},
		},
	)
	if err != nil {
		t.Fatalf("runProductPlanFlowWithDeps returned error: %v", err)
	}
	if !collectCalled {
		t.Fatal("collectAnswers should be called")
	}
	if !generateCalled {
		t.Fatal("generatePayload should be called")
	}
	if !strings.Contains(out.String(), "Product planning preflight complete (update_selected).") {
		t.Fatalf("output %q missing update_selected completion line", out.String())
	}
}

func TestRunProductPlanFlowWithDeps_UpdateSelectedInvalidSelectionStopsBeforeStages(t *testing.T) {
	dir := t.TempDir()
	productDir := filepath.Join(dir, template.HalDir, template.ProductDir)
	if err := os.MkdirAll(productDir, 0755); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", productDir, err)
	}
	if err := os.WriteFile(filepath.Join(productDir, template.ProductRoadmapFile), []byte("existing\n"), 0644); err != nil {
		t.Fatalf("WriteFile(roadmap) error = %v", err)
	}

	collectCalled := false
	generateCalled := false
	var out bytes.Buffer
	err := runProductPlanFlowWithDeps(
		context.Background(),
		productPlanRunOptions{
			Dir: dir,
			In:  strings.NewReader("2\nx\n"),
			Out: &out,
		},
		productPlanFlowDeps{
			collectAnswers: func(in io.Reader, out io.Writer, targets product.SelectedTargets) (product.CollectedAnswers, error) {
				_ = in
				_ = out
				_ = targets
				collectCalled = true
				return product.CollectedAnswers{}, nil
			},
			generatePayload: func(ctx context.Context, input productPlanGenerateInput) (product.GeneratedPayload, error) {
				_ = ctx
				_ = input
				generateCalled = true
				return product.GeneratedPayload{}, nil
			},
		},
	)
	if err == nil {
		t.Fatal("expected invalid target selection error, got nil")
	}

	wantErr := "invalid product target selection \"x\" (use mission/roadmap/tech-stack or m/r/t)"
	if err.Error() != wantErr {
		t.Fatalf("error = %q, want %q", err.Error(), wantErr)
	}
	if collectCalled {
		t.Fatal("collectAnswers should not be called for invalid selections")
	}
	if generateCalled {
		t.Fatal("generatePayload should not be called for invalid selections")
	}
}

func TestCollectProductPlanAnswers_AsksOnlySelectedTargets(t *testing.T) {
	var out bytes.Buffer
	answers, err := collectProductPlanAnswers(
		strings.NewReader("Ship the fastest onboarding flow.\nGo 1.25 + Postgres + Terraform.\n"),
		&out,
		product.SelectedTargets{
			Mission:   true,
			TechStack: true,
		},
	)
	if err != nil {
		t.Fatalf("collectProductPlanAnswers returned error: %v", err)
	}

	if len(answers.Mission) != 1 {
		t.Fatalf("len(answers.Mission) = %d, want 1", len(answers.Mission))
	}
	if answers.Mission[0].Answer != "Ship the fastest onboarding flow." {
		t.Fatalf("mission answer = %q, want explicit input", answers.Mission[0].Answer)
	}
	if len(answers.Roadmap) != 0 {
		t.Fatalf("len(answers.Roadmap) = %d, want 0 for unselected target", len(answers.Roadmap))
	}
	if len(answers.TechStack) != 1 {
		t.Fatalf("len(answers.TechStack) = %d, want 1", len(answers.TechStack))
	}
	if answers.TechStack[0].Answer != "Go 1.25 + Postgres + Terraform." {
		t.Fatalf("tech-stack answer = %q, want explicit input", answers.TechStack[0].Answer)
	}

	output := out.String()
	if !strings.Contains(output, "Mission Questions:") {
		t.Fatalf("output %q missing mission section", output)
	}
	if strings.Contains(output, "Roadmap Questions:") {
		t.Fatalf("output %q should not include roadmap section", output)
	}
	if !strings.Contains(output, "Tech Stack Questions:") {
		t.Fatalf("output %q missing tech-stack section", output)
	}
}

func TestCollectProductPlanAnswers_EmptyAnswersUseDefaults(t *testing.T) {
	var out bytes.Buffer
	answers, err := collectProductPlanAnswers(
		strings.NewReader("\n\n\n"),
		&out,
		product.SelectedTargets{
			Mission:   true,
			Roadmap:   true,
			TechStack: true,
		},
	)
	if err != nil {
		t.Fatalf("collectProductPlanAnswers returned error: %v", err)
	}

	if len(answers.Mission) != 1 || answers.Mission[0].Answer != productMissionDefaultAnswer {
		t.Fatalf("mission answers = %+v, want deterministic default %q", answers.Mission, productMissionDefaultAnswer)
	}
	if len(answers.Roadmap) != 1 || answers.Roadmap[0].Answer != productRoadmapDefaultAnswer {
		t.Fatalf("roadmap answers = %+v, want deterministic default %q", answers.Roadmap, productRoadmapDefaultAnswer)
	}
	if len(answers.TechStack) != 1 || answers.TechStack[0].Answer != productTechStackDefaultAnswer {
		t.Fatalf("tech-stack answers = %+v, want deterministic default %q", answers.TechStack, productTechStackDefaultAnswer)
	}
}

func TestCollectProductPlanAnswers_TechStackUsesExplicitUserInput(t *testing.T) {
	var out bytes.Buffer
	input := "Go 1.25, Postgres, OpenTelemetry, SLOs at p95<250ms.\n"
	answers, err := collectProductPlanAnswers(
		strings.NewReader(input),
		&out,
		product.SelectedTargets{TechStack: true},
	)
	if err != nil {
		t.Fatalf("collectProductPlanAnswers returned error: %v", err)
	}
	if len(answers.TechStack) != 1 {
		t.Fatalf("len(answers.TechStack) = %d, want 1", len(answers.TechStack))
	}
	if answers.TechStack[0].Answer != strings.TrimSpace(input) {
		t.Fatalf("tech-stack answer = %q, want explicit user input %q", answers.TechStack[0].Answer, strings.TrimSpace(input))
	}
	if answers.TechStack[0].Answer == productTechStackDefaultAnswer {
		t.Fatalf("tech-stack answer should not fall back to default when explicit input is provided")
	}
	if len(answers.Mission) != 0 || len(answers.Roadmap) != 0 {
		t.Fatalf("non-selected answers should remain empty, got mission=%d roadmap=%d", len(answers.Mission), len(answers.Roadmap))
	}
}
