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
	stat               func(name string) (os.FileInfo, error)
	loadExistingFiles  func(projectDir string) (product.ExistingFiles, error)
	selectMode         func(in io.Reader, out io.Writer) (productPlanMode, error)
	selectTargets      func(in io.Reader, out io.Writer) (product.SelectedTargets, error)
	collectAnswers     func(in io.Reader, out io.Writer, targets product.SelectedTargets) (product.CollectedAnswers, error)
	generatePayload    func(ctx context.Context, input productPlanGenerateInput) (product.GeneratedPayload, error)
	writeSelectedFiles func(projectDir string, targets product.SelectedTargets, payload product.GeneratedPayload) error
}

type productPlanGenerateInput struct {
	Engine   string
	Targets  product.SelectedTargets
	Answers  product.CollectedAnswers
	Existing product.ExistingFiles
}

type productPlanGenerateDeps struct {
	prompt func(ctx context.Context, engineName, prompt string) (string, error)
}

var defaultProductPlanDeps = productPlanDeps{
	run: runProductPlanFlow,
}

var defaultProductPlanGenerateDeps = productPlanGenerateDeps{
	prompt: promptProductPlanWithEngine,
}

var defaultProductPlanFlowDeps = productPlanFlowDeps{
	stat:               os.Stat,
	loadExistingFiles:  product.LoadExistingFiles,
	selectMode:         promptProductPlanMode,
	selectTargets:      promptProductPlanTargets,
	collectAnswers:     collectProductPlanAnswers,
	generatePayload:    generateProductPlanPayload,
	writeSelectedFiles: product.WriteSelectedFiles,
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

Use this command to maintain long-lived product context.
Use 'hal plan' to create feature-specific PRDs.`,
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
	if deps.writeSelectedFiles == nil {
		deps.writeSelectedFiles = defaultProductPlanFlowDeps.writeSelectedFiles
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

	payload, err := deps.generatePayload(ctx, productPlanGenerateInput{
		Engine:   opts.Engine,
		Targets:  selectedTargets,
		Answers:  answers,
		Existing: existing,
	})
	if err != nil {
		return fmt.Errorf("generate product payload: %w", err)
	}

	changes := plannedProductFileChanges(selectedTargets, payload, existing)
	if err := deps.writeSelectedFiles(opts.Dir, selectedTargets, payload); err != nil {
		return fmt.Errorf("write selected product files: %w", err)
	}

	writeProductPlanSuccess(opts.Out, mode, changes)
	return nil
}

type productFileChange struct {
	name   string
	action string
}

func plannedProductFileChanges(targets product.SelectedTargets, payload product.GeneratedPayload, existing product.ExistingFiles) []productFileChange {
	changes := make([]productFileChange, 0, len(template.ProductFiles()))
	if targets.Mission && payload.Mission != nil {
		changes = append(changes, productFileChange{
			name:   template.ProductMissionFile,
			action: fileChangeAction(existing.Mission.Exists),
		})
	}
	if targets.Roadmap && payload.Roadmap != nil {
		changes = append(changes, productFileChange{
			name:   template.ProductRoadmapFile,
			action: fileChangeAction(existing.Roadmap.Exists),
		})
	}
	if targets.TechStack && payload.TechStack != nil {
		changes = append(changes, productFileChange{
			name:   template.ProductTechStackFile,
			action: fileChangeAction(existing.TechStack.Exists),
		})
	}
	return changes
}

func fileChangeAction(existed bool) string {
	if existed {
		return "updated"
	}
	return "created"
}

func writeProductPlanSuccess(out io.Writer, mode productPlanMode, changes []productFileChange) {
	fmt.Fprintf(out, "Product planning complete (%s).\n", mode)
	if len(changes) == 0 {
		fmt.Fprintln(out, "No product files were created or updated.")
		return
	}

	fmt.Fprintln(out, "Created/updated files:")
	for _, change := range changes {
		fmt.Fprintf(out, "- .hal/product/%s (%s)\n", change.name, change.action)
	}
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
	reader := ensureBufferedReader(in)
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
	reader := ensureBufferedReader(in)

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

func generateProductPlanPayload(ctx context.Context, input productPlanGenerateInput) (product.GeneratedPayload, error) {
	return generateProductPlanPayloadWithDeps(ctx, input, defaultProductPlanGenerateDeps)
}

func promptProductPlanWithEngine(ctx context.Context, engineName, prompt string) (string, error) {
	eng, err := newEngine(engineName)
	if err != nil {
		return "", fmt.Errorf("create %s engine: %w", engineName, err)
	}

	response, err := eng.Prompt(ctx, prompt)
	if err != nil {
		return "", fmt.Errorf("%s engine prompt failed: %w", engineName, err)
	}

	return response, nil
}

func generateProductPlanPayloadWithDeps(ctx context.Context, input productPlanGenerateInput, deps productPlanGenerateDeps) (product.GeneratedPayload, error) {
	if deps.prompt == nil {
		deps.prompt = defaultProductPlanGenerateDeps.prompt
	}

	prompt := buildProductPlanGeneratePrompt(input)
	response, err := deps.prompt(ctx, input.Engine, prompt)
	if err != nil {
		return product.GeneratedPayload{}, fmt.Errorf("run product generation prompt: %w", err)
	}

	payload, parseErr := product.ParseGeneratedPayloadForTargets([]byte(response), input.Targets)
	if parseErr == nil {
		return payload, nil
	}

	repairPrompt := buildProductPlanRepairPrompt(input, prompt, response)
	repaired, repairErr := deps.prompt(ctx, input.Engine, repairPrompt)
	if repairErr != nil {
		return product.GeneratedPayload{}, fmt.Errorf("product payload JSON parse failed (%v); repair attempt failed: %w; rerun 'hal product plan' or try a different --engine", parseErr, repairErr)
	}

	repairedPayload, repairParseErr := product.ParseGeneratedPayloadForTargets([]byte(repaired), input.Targets)
	if repairParseErr != nil {
		return product.GeneratedPayload{}, fmt.Errorf("product payload JSON parse failed (%v); repaired response is still invalid: %w; rerun 'hal product plan' or try a different --engine", parseErr, repairParseErr)
	}

	return repairedPayload, nil
}

func buildProductPlanGeneratePrompt(input productPlanGenerateInput) string {
	selectedFiles := selectedProductFiles(input.Targets)

	var sb strings.Builder
	sb.WriteString("You are generating durable product context files for hal product plan.\n")
	sb.WriteString("Use only the provided selected context and return strict JSON output.\n\n")

	sb.WriteString("## Selected Targets\n")
	for _, file := range selectedFiles {
		fmt.Fprintf(&sb, "- %s\n", file)
	}

	sb.WriteString("\n## Interview Answers (selected targets only)\n")
	appendProductInterviewAnswerSections(&sb, input.Targets, input.Answers)

	sb.WriteString("\n## Existing File Content (selected targets only)\n")
	appendProductExistingFileSections(&sb, input.Targets, input.Existing)

	sb.WriteString("\n## Output Contract\n")
	sb.WriteString("Return ONLY valid JSON (no markdown code fences, no prose).\n")
	sb.WriteString("Include ONLY these selected filename keys:\n")
	for _, file := range selectedFiles {
		fmt.Fprintf(&sb, "- %q\n", file)
	}
	sb.WriteString("Each value must be a string containing the full markdown content for that file.\n")
	sb.WriteString("Do not include unknown keys.\n\n")
	sb.WriteString("Return JSON in this shape:\n")
	sb.WriteString("{\n")
	for i, file := range selectedFiles {
		suffix := ","
		if i == len(selectedFiles)-1 {
			suffix = ""
		}
		fmt.Fprintf(&sb, "  %q: \"<full markdown content>\"%s\n", file, suffix)
	}
	sb.WriteString("}")

	return sb.String()
}

func buildProductPlanRepairPrompt(input productPlanGenerateInput, originalPrompt, previousResponse string) string {
	selectedFiles := selectedProductFiles(input.Targets)

	var sb strings.Builder
	sb.WriteString("The previous response did not match the required JSON output contract for hal product plan.\n")
	sb.WriteString("Repair the response and return ONLY valid JSON (no markdown fences, no prose).\n")
	sb.WriteString("Include ONLY these selected filename keys:\n")
	for _, file := range selectedFiles {
		fmt.Fprintf(&sb, "- %q\n", file)
	}
	sb.WriteString("Each selected key value must be a string containing full markdown content.\n\n")

	sb.WriteString("Original generation instructions:\n")
	sb.WriteString(originalPrompt)
	sb.WriteString("\n\n")

	sb.WriteString("Previous response:\n")
	sb.WriteString(previousResponse)
	sb.WriteString("\n")

	return sb.String()
}

func selectedProductFiles(targets product.SelectedTargets) []string {
	files := make([]string, 0, len(template.ProductFiles()))
	if targets.Mission {
		files = append(files, template.ProductMissionFile)
	}
	if targets.Roadmap {
		files = append(files, template.ProductRoadmapFile)
	}
	if targets.TechStack {
		files = append(files, template.ProductTechStackFile)
	}
	return files
}

func appendProductInterviewAnswerSections(sb *strings.Builder, targets product.SelectedTargets, answers product.CollectedAnswers) {
	if targets.Mission {
		appendProductInterviewAnswerSection(sb, template.ProductMissionFile, answers.Mission)
	}
	if targets.Roadmap {
		appendProductInterviewAnswerSection(sb, template.ProductRoadmapFile, answers.Roadmap)
	}
	if targets.TechStack {
		appendProductInterviewAnswerSection(sb, template.ProductTechStackFile, answers.TechStack)
	}
}

func appendProductInterviewAnswerSection(sb *strings.Builder, fileName string, answers []product.InterviewAnswer) {
	fmt.Fprintf(sb, "### %s\n", fileName)
	if len(answers) == 0 {
		sb.WriteString("- (no answers provided)\n")
		return
	}
	for _, answer := range answers {
		fmt.Fprintf(sb, "- Q: %s\n", answer.Question)
		fmt.Fprintf(sb, "  A: %s\n", answer.Answer)
	}
}

func appendProductExistingFileSections(sb *strings.Builder, targets product.SelectedTargets, existing product.ExistingFiles) {
	if targets.Mission {
		appendProductExistingFileSection(sb, template.ProductMissionFile, existing.Mission)
	}
	if targets.Roadmap {
		appendProductExistingFileSection(sb, template.ProductRoadmapFile, existing.Roadmap)
	}
	if targets.TechStack {
		appendProductExistingFileSection(sb, template.ProductTechStackFile, existing.TechStack)
	}
}

func appendProductExistingFileSection(sb *strings.Builder, fileName string, state product.FileState) {
	if state.Exists {
		fmt.Fprintf(sb, "### %s (existing)\n", fileName)
		sb.WriteString("```markdown\n")
		sb.WriteString(state.Content)
		if !strings.HasSuffix(state.Content, "\n") {
			sb.WriteString("\n")
		}
		sb.WriteString("```\n")
		return
	}

	fmt.Fprintf(sb, "### %s (missing)\n", fileName)
	sb.WriteString("<missing>\n")
}
