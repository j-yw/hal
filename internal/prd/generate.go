package prd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/skills"
	"github.com/jywlabs/hal/internal/template"
)

// GenerateWithEngine runs the two-phase PRD generation using the prd skill.
// Phase 1: Generate clarifying questions
// Phase 2: Collect answers and generate PRD
func GenerateWithEngine(ctx context.Context, eng engine.Engine, description string, format string, display *engine.Display) (string, error) {
	// Load prd skill content
	prdSkill, err := skills.LoadSkill("prd")
	if err != nil {
		return "", fmt.Errorf("failed to load prd skill: %w", err)
	}

	// Get project context
	projectInfo := getProjectContext()

	// Phase 1: Generate clarifying questions
	if display != nil {
		display.ShowPhase(1, 2, "Questions")
	}
	questions, err := generateQuestions(ctx, eng, prdSkill, description, projectInfo, display)
	if err != nil {
		return "", fmt.Errorf("failed to generate questions: %w", err)
	}

	// Collect answers from user (uses styled display)
	answers, err := collectAnswersStyled(questions, display)
	if err != nil {
		return "", fmt.Errorf("failed to collect answers: %w", err)
	}

	// Phase 2: Generate PRD
	if display != nil {
		display.ShowPhase(2, 2, "Generate")
	}
	prdContent, err := generatePRD(ctx, eng, prdSkill, description, questions, answers, projectInfo, display)
	if err != nil {
		return "", fmt.Errorf("failed to generate PRD: %w", err)
	}

	// Determine output path and write
	var outputPath string
	if format == "json" {
		outputPath = filepath.Join(template.HalDir, template.PRDFile)
		// Convert to JSON using hal skill
		halSkill, err := skills.LoadSkill("hal")
		if err != nil {
			return "", fmt.Errorf("failed to load hal skill: %w", err)
		}
		jsonContent, err := convertPRDToJSON(ctx, eng, halSkill, prdContent, outputPath, display)
		if err != nil {
			return "", fmt.Errorf("failed to convert PRD to JSON: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
			return "", err
		}
		if err := os.WriteFile(outputPath, []byte(jsonContent), 0644); err != nil {
			return "", err
		}
	} else {
		// Write markdown to .hal/
		featureName := extractFeatureNameFromDescription(description)
		outputPath = filepath.Join(template.HalDir, fmt.Sprintf("prd-%s.md", featureName))
		if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
			return "", err
		}
		if err := os.WriteFile(outputPath, []byte(prdContent), 0644); err != nil {
			return "", err
		}
	}

	return outputPath, nil
}

func generateQuestions(ctx context.Context, eng engine.Engine, skill, description, projectInfo string, display *engine.Display) ([]Question, error) {
	prompt := fmt.Sprintf(`You are helping generate a Product Requirements Document.

<skill>
%s
</skill>

Project context:
%s

Feature request: %s

Generate 3-5 clarifying questions with A/B/C/D options to understand:
- Primary goal and problem being solved
- Target users and scope
- Key functionality and boundaries
- Success criteria

IMPORTANT: Do NOT use any tools (no Read, Write, Bash, etc.). Do NOT write any files.
Return ONLY a JSON object (no markdown, no explanation):
{
  "questions": [
    {
      "number": 1,
      "text": "Question text here?",
      "options": [
        {"letter": "A", "label": "Option A"},
        {"letter": "B", "label": "Option B"},
        {"letter": "C", "label": "Option C"},
        {"letter": "D", "label": "Other (specify)"}
      ]
    }
  ]
}`, skill, projectInfo, description)

	var response string
	var err error
	if display != nil {
		response, err = eng.StreamPrompt(ctx, prompt, display)
		if err != nil && shouldFallbackFromStream(err) {
			// Some CLIs are less stable in streaming mode for very large prompts.
			response, err = eng.Prompt(ctx, prompt)
		}
	} else {
		response, err = eng.Prompt(ctx, prompt)
	}
	if err != nil {
		return nil, err
	}

	questions, parseErr := parseQuestionsResponse(response)
	if parseErr == nil {
		return questions, nil
	}

	// Retry once by asking the model to reformat/regenerate strict JSON.
	repairPrompt := fmt.Sprintf(`The previous response did not match the required JSON schema.

Feature request:
%s

Previous response:
%s

Generate 3-5 clarifying questions and return ONLY valid JSON in this exact shape:
{
  "questions": [
    {
      "number": 1,
      "text": "Question text here?",
      "options": [
        {"letter": "A", "label": "Option A"},
        {"letter": "B", "label": "Option B"},
        {"letter": "C", "label": "Option C"},
        {"letter": "D", "label": "Other (specify)"}
      ]
    }
  ]
}

Do not use markdown fences. Do not include explanation.`, description, response)

	repaired, repairErr := eng.Prompt(ctx, repairPrompt)
	if repairErr != nil {
		return nil, fmt.Errorf("failed to repair questions JSON after initial parse error (%v): %w", parseErr, repairErr)
	}

	questions, repairParseErr := parseQuestionsResponse(repaired)
	if repairParseErr != nil {
		return nil, fmt.Errorf("failed to parse repaired questions response after initial parse error (%v): %w", parseErr, repairParseErr)
	}

	return questions, nil
}

func shouldFallbackFromStream(err error) bool {
	if err == nil {
		return false
	}
	if engine.RequiresOutputFallback(err) {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "timed out") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "deadline exceeded") ||
		strings.Contains(msg, "canceled") ||
		strings.Contains(msg, "cancelled") {
		return false
	}

	return true
}

func parseQuestionsResponse(response string) ([]Question, error) {
	response = strings.TrimSpace(response)

	// Handle markdown code blocks
	if strings.Contains(response, "```") {
		lines := strings.Split(response, "\n")
		var jsonLines []string
		inBlock := false
		for _, line := range lines {
			if strings.HasPrefix(line, "```") {
				inBlock = !inBlock
				continue
			}
			if inBlock {
				jsonLines = append(jsonLines, line)
			}
		}
		response = strings.Join(jsonLines, "\n")
	}

	// Find JSON object
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")
	if start == -1 || end == -1 || end < start {
		return nil, fmt.Errorf("no JSON found in response")
	}
	response = response[start : end+1]

	var qr QuestionsResponse
	if err := json.Unmarshal([]byte(response), &qr); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	return qr.Questions, nil
}

// collectAnswersStyled displays all questions at once and collects answers in a
// single batch input like "1A, 2B, 3C, 4B, 5A".
func collectAnswersStyled(questions []Question, display *engine.Display) (map[int]string, error) {
	reader := bufio.NewReader(os.Stdin)

	// Show all questions at once
	for _, q := range questions {
		displayOpts := make([]engine.QuestionOption, len(q.Options))
		for i, opt := range q.Options {
			displayOpts[i] = engine.QuestionOption{
				Letter:      opt.Letter,
				Label:       opt.Label,
				Recommended: strings.Contains(strings.ToLower(opt.Label), "recommend"),
			}
		}

		if display != nil {
			display.ShowQuestion(q.Number, q.Text, displayOpts)
		} else {
			fmt.Printf("\n%d. %s\n", q.Number, q.Text)
			for _, opt := range q.Options {
				fmt.Printf("   %s. %s\n", opt.Letter, opt.Label)
			}
		}
	}

	// Build option lookup: questionNumber -> letter -> label
	optionMap := buildOptionMap(questions)

	// Collect answers with retry on error or missing questions
	example := buildAnswerExample(questions)
	fmt.Printf("\nAnswer all questions, e.g. %s\n", example)
	fmt.Print("Your answers: ")

	var answers map[int]string
	for {
		input, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}

		answers, err = parseBatchAnswers(strings.TrimSpace(input), optionMap)
		if err != nil {
			fmt.Printf("  ✗ %s\n", err)
			fmt.Print("Your answers: ")
			continue
		}

		// Check all questions are answered
		missing := findMissingQuestions(questions, answers)
		if len(missing) > 0 {
			fmt.Printf("  ✗ Missing answers for: %s\n", formatMissingQuestions(missing))
			fmt.Print("Your answers: ")
			continue
		}

		break
	}

	// Collect custom text for "Other" options — iterate in question order (deterministic)
	for _, q := range questions {
		label, ok := answers[q.Number]
		if !ok {
			continue
		}
		if isOtherOption(label) {
			fmt.Printf("Q%d — please specify: ", q.Number)
			custom, err := reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
			answers[q.Number] = strings.TrimSpace(custom)
		}
	}

	return answers, nil
}

// findMissingQuestions returns question numbers that have no answer.
func findMissingQuestions(questions []Question, answers map[int]string) []int {
	var missing []int
	for _, q := range questions {
		if _, ok := answers[q.Number]; !ok {
			missing = append(missing, q.Number)
		}
	}
	return missing
}

// formatMissingQuestions formats a list of missing question numbers like "Q1, Q3, Q5".
func formatMissingQuestions(nums []int) string {
	parts := make([]string, len(nums))
	for i, n := range nums {
		parts[i] = fmt.Sprintf("Q%d", n)
	}
	return strings.Join(parts, ", ")
}

// isOtherOption checks if a label represents an "Other (specify)" option.
func isOtherOption(label string) bool {
	lower := strings.ToLower(label)
	return strings.Contains(lower, "other")
}

// buildAnswerExample generates an example answer string like "1A, 2B, 3C".
func buildAnswerExample(questions []Question) string {
	parts := make([]string, 0, len(questions))
	letters := []string{"A", "B", "C", "D"}
	for i, q := range questions {
		letter := letters[i%len(letters)]
		parts = append(parts, fmt.Sprintf("%d%s", q.Number, letter))
	}
	return strings.Join(parts, ", ")
}

// buildOptionMap creates a lookup: questionNumber -> uppercase letter -> label.
func buildOptionMap(questions []Question) map[int]map[string]string {
	m := make(map[int]map[string]string, len(questions))
	for _, q := range questions {
		opts := make(map[string]string, len(q.Options))
		for _, opt := range q.Options {
			opts[strings.ToUpper(opt.Letter)] = opt.Label
		}
		m[q.Number] = opts
	}
	return m
}

// parseBatchAnswers parses a compact answer string like "1A, 2B, 3C" into a map
// of question number -> selected label. Supports formats:
//   - "1A, 2B, 3C"        (with commas)
//   - "1A 2B 3C"           (space-separated)
//   - "1a,2b,3c"           (lowercase, no spaces)
//   - "1A,2B,3C,4B,5A"    (mixed)
//   - "1A2B3C"             (fully concatenated)
func parseBatchAnswers(input string, optionMap map[int]map[string]string) (map[int]string, error) {
	answers := make(map[int]string)

	// Normalize: replace commas with spaces, split concatenated tokens (1A2B → 1A 2B),
	// then split on whitespace.
	input = strings.ReplaceAll(input, ",", " ")
	input = splitConcatenatedAnswers(input)
	tokens := strings.Fields(input)

	if len(tokens) == 0 {
		return nil, fmt.Errorf("no answers provided")
	}

	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if len(token) < 2 {
			return nil, fmt.Errorf("invalid answer %q — expected format like 1A", token)
		}

		// Split into number prefix and letter suffix
		// Find where digits end: "1A" → num="1" letter="A", "12B" → num="12" letter="B"
		splitIdx := 0
		for splitIdx < len(token) && token[splitIdx] >= '0' && token[splitIdx] <= '9' {
			splitIdx++
		}
		if splitIdx == 0 || splitIdx == len(token) {
			return nil, fmt.Errorf("invalid answer %q — expected format like 1A", token)
		}

		numStr := token[:splitIdx]
		letter := strings.ToUpper(token[splitIdx:])

		var qNum int
		if _, err := fmt.Sscanf(numStr, "%d", &qNum); err != nil {
			return nil, fmt.Errorf("invalid question number in %q", token)
		}

		opts, ok := optionMap[qNum]
		if !ok {
			return nil, fmt.Errorf("unknown question number %d in %q", qNum, token)
		}

		label, ok := opts[letter]
		if !ok {
			validLetters := make([]string, 0, len(opts))
			for l := range opts {
				validLetters = append(validLetters, l)
			}
			sort.Strings(validLetters)
			return nil, fmt.Errorf("invalid option %s for question %d (valid: %s)", letter, qNum, strings.Join(validLetters, ", "))
		}

		answers[qNum] = label
	}

	return answers, nil
}

// splitConcatenatedAnswers inserts spaces between concatenated answer pairs.
// "1A2B3C" → "1A 2B 3C", "12A3B" → "12A 3B"
// Splits at boundaries where a letter is immediately followed by a digit.
func splitConcatenatedAnswers(input string) string {
	var result strings.Builder
	for i := 0; i < len(input); i++ {
		result.WriteByte(input[i])
		if i+1 < len(input) && isLetter(input[i]) && isDigit(input[i+1]) {
			result.WriteByte(' ')
		}
	}
	return result.String()
}

func isLetter(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func generatePRD(ctx context.Context, eng engine.Engine, skill, description string, questions []Question, answers map[int]string, projectInfo string, display *engine.Display) (string, error) {
	// Format answers with question text so the engine has full context.
	// Output: "1. What's the primary goal? → Performance optimization"
	questionTextByNum := make(map[int]string, len(questions))
	for _, q := range questions {
		questionTextByNum[q.Number] = q.Text
	}

	var answerText strings.Builder
	for _, q := range questions {
		if ans, ok := answers[q.Number]; ok {
			answerText.WriteString(fmt.Sprintf("%d. %s → %s\n", q.Number, q.Text, ans))
		}
	}

	prompt := fmt.Sprintf(`You are generating a Product Requirements Document.

<skill>
%s
</skill>

Project context:
%s

Feature request: %s

User's answers to clarifying questions:
%s

Generate a complete PRD following the skill format. Requirements:
- Each user story must be small enough to complete in one iteration
- Acceptance criteria must be verifiable (not vague)
- Include "Typecheck passes" for all stories
- Include "%s" for UI stories
- Order: schema changes → backend → frontend

IMPORTANT: Do NOT use any tools (no Read, Write, Bash, etc.). Do NOT write any files.
File saving is handled by the caller. Return ONLY the markdown PRD content (no JSON, no code blocks wrapping it).`, skill, projectInfo, description, answerText.String(), template.BrowserVerificationCriterion)

	if display != nil {
		return eng.StreamPrompt(ctx, prompt, display)
	}
	return eng.Prompt(ctx, prompt)
}

func convertPRDToJSON(ctx context.Context, eng engine.Engine, skill, prdContent, outPath string, display *engine.Display) (string, error) {
	var (
		beforeOutput     *outputSnapshot
		err              error
		branchResolution = resolveMarkdownBranch(prdContent)
		targetBranchName = branchResolution.Name
	)

	if outPath != "" {
		beforeOutput, err = readOutputSnapshot(outPath)
		if err != nil {
			return "", fmt.Errorf("failed to inspect output file before conversion: %w", err)
		}
		targetBranchName = selectConvertBranchName("", branchResolution)
	}

	prompt := buildConversionPrompt(skill, prdContent, targetBranchName, false)

	var response string
	if display != nil {
		response, err = eng.StreamPrompt(ctx, prompt, display)
	} else {
		response, err = eng.Prompt(ctx, prompt)
	}
	if err != nil {
		if engine.RequiresOutputFallback(err) {
			fallbackJSON, usedFallback, fallbackErr := fallbackJSONFromOutput(outPath, beforeOutput)
			if fallbackErr != nil {
				return "", fmt.Errorf("engine prompt failed: %w (and output fallback failed: %v)", err, fallbackErr)
			}
			if usedFallback {
				response = fallbackJSON
			} else {
				return "", err
			}
		} else {
			return "", err
		}
	}

	// Extract and validate JSON
	jsonContent, err := extractJSONFromResponse(response)
	if err != nil {
		if outPath == "" {
			return "", err
		}

		fallbackJSON, usedFallback, fallbackErr := fallbackJSONFromOutput(outPath, beforeOutput)
		if fallbackErr != nil {
			return "", fmt.Errorf("failed to extract JSON from response (%v) and output fallback failed: %w", err, fallbackErr)
		}
		if !usedFallback {
			return "", fmt.Errorf("failed to extract JSON from response: %w", err)
		}
		jsonContent = fallbackJSON
	}

	if targetBranchName != "" {
		jsonContent, err = setPRDBranchName(jsonContent, targetBranchName)
		if err != nil {
			return "", fmt.Errorf("failed to pin converted branchName: %w", err)
		}
	}

	return jsonContent, nil
}

func getProjectContext() string {
	var context strings.Builder
	context.WriteString("Codebase information:\n")

	// Check for common project files
	if _, err := os.Stat("package.json"); err == nil {
		context.WriteString("- Node.js/JavaScript project (package.json present)\n")
	}
	if _, err := os.Stat("go.mod"); err == nil {
		context.WriteString("- Go project (go.mod present)\n")
	}
	if _, err := os.Stat("Cargo.toml"); err == nil {
		context.WriteString("- Rust project (Cargo.toml present)\n")
	}
	if _, err := os.Stat("requirements.txt"); err == nil {
		context.WriteString("- Python project (requirements.txt present)\n")
	}
	if _, err := os.Stat("pyproject.toml"); err == nil {
		context.WriteString("- Python project (pyproject.toml present)\n")
	}

	// Check for common frameworks
	if _, err := os.Stat("next.config.js"); err == nil {
		context.WriteString("- Next.js framework detected\n")
	}
	if _, err := os.Stat("next.config.ts"); err == nil {
		context.WriteString("- Next.js framework detected\n")
	}
	if _, err := os.Stat("vite.config.ts"); err == nil {
		context.WriteString("- Vite build tool detected\n")
	}

	return context.String()
}

func extractFeatureNameFromDescription(description string) string {
	// Convert to kebab-case
	name := strings.ToLower(description)
	// Replace spaces and special chars with hyphens
	re := regexp.MustCompile(`[^a-z0-9]+`)
	name = re.ReplaceAllString(name, "-")
	// Trim hyphens
	name = strings.Trim(name, "-")
	// Truncate if too long
	if len(name) > 50 {
		name = name[:50]
		// Don't cut in middle of word
		if lastHyphen := strings.LastIndex(name, "-"); lastHyphen > 30 {
			name = name[:lastHyphen]
		}
	}
	return name
}
