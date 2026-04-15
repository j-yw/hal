package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/product"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

var productPlanEngineFlag string

type productPlanRunOptions struct {
	Dir    string
	Engine string
	In     io.Reader
	Out    io.Writer
	ErrOut io.Writer
}

type productPlanDeps struct {
	run func(ctx context.Context, opts productPlanRunOptions) error
}

type productPlanMode string

const (
	productPlanModeReplaceAll     productPlanMode = "replace_all"
	productPlanModeUpdateSelected productPlanMode = "update_selected"
	productPlanModeCancel         productPlanMode = "cancel"
)

type productPlanFlowDeps struct {
	stat              func(name string) (os.FileInfo, error)
	loadExistingFiles func(projectDir string) (product.ExistingFiles, error)
	selectMode        func(in io.Reader, out io.Writer) (productPlanMode, error)
}

var defaultProductPlanDeps = productPlanDeps{
	run: runProductPlanFlow,
}

var defaultProductPlanFlowDeps = productPlanFlowDeps{
	stat:              os.Stat,
	loadExistingFiles: product.LoadExistingFiles,
	selectMode:        promptProductPlanMode,
}

var productCmd = &cobra.Command{
	Use:   "product",
	Short: "Plan and maintain durable product context",
	Long: `Plan and maintain durable product context in .hal/product/.

Use 'hal product plan' to generate or update mission, roadmap, and tech-stack docs.`,
	Example: `  hal product plan
  hal product plan --engine codex`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

var productPlanCmd = &cobra.Command{
	Use:   "plan",
	Short: "Generate or update product context documents",
	Long: `Generate or update durable product context files:
  - .hal/product/mission.md
  - .hal/product/roadmap.md
  - .hal/product/tech-stack.md

This command currently provides preflight checks and mode selection; next stories add interactive generation.`,
	Example: `  hal product plan
  hal product plan --engine claude`,
	Args: noArgsValidation(),
	RunE: runProductPlan,
}

func init() {
	productPlanCmd.Flags().StringVarP(&productPlanEngineFlag, "engine", "e", "codex", "Engine to use (claude, codex, pi)")
	productCmd.AddCommand(productPlanCmd)
	rootCmd.AddCommand(productCmd)
}

func runProductPlan(cmd *cobra.Command, args []string) error {
	return runProductPlanWithDeps(cmd, args, defaultProductPlanDeps)
}

func runProductPlanWithDeps(cmd *cobra.Command, args []string, deps productPlanDeps) error {
	_ = args

	if deps.run == nil {
		deps.run = runProductPlanFlow
	}

	engineName, err := resolveEngine(cmd, "engine", productPlanEngineFlag, ".")
	if err != nil {
		return exitWithCode(cmd, ExitCodeValidation, err)
	}

	ctx := context.Background()
	in := io.Reader(os.Stdin)
	out := io.Writer(os.Stdout)
	errOut := io.Writer(os.Stderr)
	if cmd != nil {
		if cmd.Context() != nil {
			ctx = cmd.Context()
		}
		in = cmd.InOrStdin()
		out = cmd.OutOrStdout()
		errOut = cmd.ErrOrStderr()
	}

	opts := productPlanRunOptions{
		Dir:    ".",
		Engine: engineName,
		In:     in,
		Out:    out,
		ErrOut: errOut,
	}
	return deps.run(ctx, opts)
}

func runProductPlanFlow(ctx context.Context, opts productPlanRunOptions) error {
	_ = ctx
	return runProductPlanFlowWithDeps(ctx, opts, defaultProductPlanFlowDeps)
}

func runProductPlanFlowWithDeps(ctx context.Context, opts productPlanRunOptions, deps productPlanFlowDeps) error {
	_ = ctx
	if opts.Dir == "" {
		opts.Dir = "."
	}
	if opts.In == nil {
		opts.In = os.Stdin
	}
	if opts.Out == nil {
		opts.Out = os.Stdout
	}

	if deps.stat == nil {
		deps.stat = os.Stat
	}
	if deps.loadExistingFiles == nil {
		deps.loadExistingFiles = product.LoadExistingFiles
	}
	if deps.selectMode == nil {
		deps.selectMode = promptProductPlanMode
	}

	halDir := filepath.Join(opts.Dir, template.HalDir)
	if _, err := deps.stat(halDir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf(".hal/ not found - run 'hal init' first")
		}
		return fmt.Errorf("check %s: %w", halDir, err)
	}

	existing, err := deps.loadExistingFiles(opts.Dir)
	if err != nil {
		return fmt.Errorf("load existing product files: %w", err)
	}

	mode := productPlanModeReplaceAll
	if hasExistingProductFiles(existing) {
		mode, err = deps.selectMode(opts.In, opts.Out)
		if err != nil {
			return err
		}
		if mode == productPlanModeCancel {
			fmt.Fprintln(opts.Out, "Cancelled product planning. No files were changed.")
			return nil
		}
	}

	fmt.Fprintf(opts.Out, "Product planning preflight complete (%s). Next stories add interactive generation and selective updates.\n", mode)
	return nil
}

func hasExistingProductFiles(existing product.ExistingFiles) bool {
	return existing.Mission.Exists || existing.Roadmap.Exists || existing.TechStack.Exists
}

func promptProductPlanMode(in io.Reader, out io.Writer) (productPlanMode, error) {
	reader := bufio.NewReader(in)
	for {
		fmt.Fprintln(out, "Existing .hal/product files found. Choose how to continue:")
		fmt.Fprintln(out, "  1) Replace all files")
		fmt.Fprintln(out, "  2) Update selected files")
		fmt.Fprintln(out, "  3) Cancel")
		fmt.Fprint(out, "Select an option [1/2/3]: ")

		line, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("read product plan mode selection: %w", err)
		}

		choice := strings.ToLower(strings.TrimSpace(line))
		switch choice {
		case "1", "r", "replace", "replace-all", "replace all":
			return productPlanModeReplaceAll, nil
		case "2", "u", "update", "update-selected", "update selected":
			return productPlanModeUpdateSelected, nil
		case "3", "c", "cancel":
			return productPlanModeCancel, nil
		}

		if errors.Is(err, io.EOF) {
			if choice == "" {
				return "", fmt.Errorf("product plan mode selection is required")
			}
			return "", fmt.Errorf("invalid product plan mode selection %q", choice)
		}

		fmt.Fprintln(out, "Invalid selection. Enter 1, 2, or 3.")
	}
}
