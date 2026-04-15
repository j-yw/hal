package cmd

import (
	"context"
	"fmt"
	"io"
	"os"

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

var defaultProductPlanDeps = productPlanDeps{
	run: runProductPlanFlow,
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

This command currently provides the execution skeleton and engine wiring.`,
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
	if opts.Out != nil {
		fmt.Fprintln(opts.Out, "Product planning flow scaffolded. Next stories add interactive generation and selective updates.")
	}
	return nil
}
