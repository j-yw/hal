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

	productMissionQuestionPrompt   = "What is the core mission for this product?"
	productRoadmapQuestionPrompt   = "What are the highest-priority milestones for the next two quarters?"
	productTechStackQuestionPrompt = "Which technologies and constraints are required for this product?"

	productMissionDefaultAnswer   = "TODO: define the core mission and user outcome for this product."
	productRoadmapDefaultAnswer   = "TODO: define the top roadmap milestones for the next two quarters."
	productTechStackDefaultAnswer = "TODO: define the required technologies and constraints explicitly."
)

type productInterviewQuestion struct {
	prompt        string
	defaultAnswer string
}

type productPlanFlowDeps struct {
	stat              func(name string) (os.FileInfo, error)
	loadExistingFiles func(projectDir string) (product.ExistingFiles, error)
	selectMode        func(in io.Reader, out io.Writer) (productPlanMode, error)
	selectTargets     func(in io.Reader, out io.Writer) (product.SelectedTargets, error)
	collectAnswers    func(in io.Reader, out io.Writer, targets product.SelectedTargets) (product.CollectedAnswers, error)
	generatePayload   func(ctx context.Context, input productPlanGenerateInput) (product.GeneratedPayload, error)
}

type productPlanGenerateInput struct {
	Engine   string
	Targets  product.SelectedTargets
	Answers  product.CollectedAnswers
	Existing product.ExistingFiles
}

var defaultProductPlanDeps = productPlanDeps{
	run: runProductPlanFlow,
}

var defaultProductPlanFlowDeps = productPlanFlowDeps{
	stat:              os.Stat,
	loadExistingFiles: product.LoadExistingFiles,
	selectMode:        promptProductPlanMode,
	selectTargets:     promptProductPlanTargets,
	collectAnswers:    collectProductPlanAnswers,
	generatePayload: func(ctx context.Context, input productPlanGenerateInput) (product.GeneratedPayload, error) {
		_ = ctx
		_ = input
		return product.GeneratedPayload{}, nil
	},
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
	if deps.selectTargets == nil {
		deps.selectTargets = promptProductPlanTargets
	}
	if deps.collectAnswers == nil {
		deps.collectAnswers = defaultProductPlanFlowDeps.collectAnswers
	}
	if deps.generatePayload == nil {
		deps.generatePayload = defaultProductPlanFlowDeps.generatePayload
	}

	promptIn := opts.In
	if _, ok := promptIn.(*bufio.Reader); !ok {
		promptIn = bufio.NewReader(promptIn)
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
	selectedTargets := allProductTargets()
	if hasExistingProductFiles(existing) {
		mode, err = deps.selectMode(promptIn, opts.Out)
		if err != nil {
			return err
		}
		if mode == productPlanModeCancel {
			fmt.Fprintln(opts.Out, "Cancelled product planning. No files were changed.")
			return nil
		}
		if mode == productPlanModeUpdateSelected {
			selectedTargets, err = deps.selectTargets(promptIn, opts.Out)
			if err != nil {
				return err
			}
		}
	}

	answers, err := deps.collectAnswers(promptIn, opts.Out, selectedTargets)
	if err != nil {
		return fmt.Errorf("collect product interview answers: %w", err)
	}

	_, err = deps.generatePayload(ctx, productPlanGenerateInput{
		Engine:   opts.Engine,
		Targets:  selectedTargets,
		Answers:  answers,
		Existing: existing,
	})
	if err != nil {
		return fmt.Errorf("generate product payload: %w", err)
	}

	fmt.Fprintf(opts.Out, "Product planning preflight complete (%s). Next stories add interactive generation and selective updates.\n", mode)
	return nil
}

func allProductTargets() product.SelectedTargets {
	return product.SelectedTargets{
		Mission:   true,
		Roadmap:   true,
		TechStack: true,
	}
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

func promptProductPlanTargets(in io.Reader, out io.Writer) (product.SelectedTargets, error) {
	reader := bufio.NewReader(in)

	fmt.Fprintln(out, "Select files to update: mission (m), roadmap (r), tech-stack (t).")
	fmt.Fprintln(out, "Examples: m,rt  |  m,r  |  mission roadmap")
	fmt.Fprint(out, "Targets: ")

	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return product.SelectedTargets{}, fmt.Errorf("read product target selection: %w", err)
	}

	return parseProductPlanTargets(line)
}

func parseProductPlanTargets(input string) (product.SelectedTargets, error) {
	normalized := strings.ToLower(strings.TrimSpace(input))
	if normalized == "" {
		return product.SelectedTargets{}, fmt.Errorf("product target selection is required")
	}

	replacer := strings.NewReplacer(",", " ", "+", " ", "/", " ", "|", " ")
	tokens := strings.Fields(replacer.Replace(normalized))
	if len(tokens) == 0 {
		return product.SelectedTargets{}, fmt.Errorf("product target selection is required")
	}

	var targets product.SelectedTargets
	for _, token := range tokens {
		if len(token) > 1 && isConciseTargetToken(token) {
			for _, ch := range token {
				if err := applyTargetToken(string(ch), &targets); err != nil {
					return product.SelectedTargets{}, err
				}
			}
			continue
		}

		if err := applyTargetToken(token, &targets); err != nil {
			return product.SelectedTargets{}, err
		}
	}

	if !targets.Mission && !targets.Roadmap && !targets.TechStack {
		return product.SelectedTargets{}, fmt.Errorf("product target selection is required")
	}

	return targets, nil
}

func isConciseTargetToken(token string) bool {
	for _, ch := range token {
		switch ch {
		case 'm', 'r', 't':
		default:
			return false
		}
	}
	return true
}

func applyTargetToken(token string, targets *product.SelectedTargets) error {
	switch token {
	case "1", "m", "mission":
		targets.Mission = true
	case "2", "r", "roadmap":
		targets.Roadmap = true
	case "3", "t", "tech", "stack", "techstack", "tech-stack":
		targets.TechStack = true
	default:
		return fmt.Errorf("invalid product target selection %q (use mission/roadmap/tech-stack or m/r/t)", token)
	}
	return nil
}

func collectProductPlanAnswers(in io.Reader, out io.Writer, targets product.SelectedTargets) (product.CollectedAnswers, error) {
	reader := ensureBufferedReader(in)
	if out == nil {
		out = io.Discard
	}

	var answers product.CollectedAnswers
	if targets.Mission {
		sectionAnswers, err := collectProductInterviewSection(reader, out, "Mission", []productInterviewQuestion{
			{
				prompt:        productMissionQuestionPrompt,
				defaultAnswer: productMissionDefaultAnswer,
			},
		})
		if err != nil {
			return product.CollectedAnswers{}, fmt.Errorf("collect mission interview answers: %w", err)
		}
		answers.Mission = sectionAnswers
	}

	if targets.Roadmap {
		sectionAnswers, err := collectProductInterviewSection(reader, out, "Roadmap", []productInterviewQuestion{
			{
				prompt:        productRoadmapQuestionPrompt,
				defaultAnswer: productRoadmapDefaultAnswer,
			},
		})
		if err != nil {
			return product.CollectedAnswers{}, fmt.Errorf("collect roadmap interview answers: %w", err)
		}
		answers.Roadmap = sectionAnswers
	}

	if targets.TechStack {
		sectionAnswers, err := collectProductInterviewSection(reader, out, "Tech Stack", []productInterviewQuestion{
			{
				prompt:        productTechStackQuestionPrompt,
				defaultAnswer: productTechStackDefaultAnswer,
			},
		})
		if err != nil {
			return product.CollectedAnswers{}, fmt.Errorf("collect tech-stack interview answers: %w", err)
		}
		answers.TechStack = sectionAnswers
	}

	return answers, nil
}

func collectProductInterviewSection(reader *bufio.Reader, out io.Writer, title string, questions []productInterviewQuestion) ([]product.InterviewAnswer, error) {
	fmt.Fprintf(out, "\n%s Questions:\n", title)

	answers := make([]product.InterviewAnswer, 0, len(questions))
	inputExhausted := false
	for i, question := range questions {
		fmt.Fprintf(out, "%d) %s\n", i+1, question.prompt)
		fmt.Fprintf(out, "Answer [%s]: ", question.defaultAnswer)

		var line string
		if !inputExhausted {
			readLine, err := reader.ReadString('\n')
			if err != nil {
				if errors.Is(err, io.EOF) {
					inputExhausted = true
				} else {
					return nil, fmt.Errorf("read answer for %q: %w", title, err)
				}
			}
			line = readLine
		}

		answer := strings.TrimSpace(line)
		if answer == "" {
			answer = question.defaultAnswer
		}

		answers = append(answers, product.InterviewAnswer{
			Question: question.prompt,
			Answer:   answer,
		})
	}

	return answers, nil
}

func ensureBufferedReader(in io.Reader) *bufio.Reader {
	if reader, ok := in.(*bufio.Reader); ok {
		return reader
	}
	if in == nil {
		in = strings.NewReader("")
	}
	return bufio.NewReader(in)
}
