package prd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jywlabs/goralph/internal/engine"
	"github.com/jywlabs/goralph/internal/skills"
)

// GenerateWithEngine runs the two-phase PRD generation using the prd skill.
// Phase 1: Generate clarifying questions
// Phase 2: Collect answers and generate PRD
func GenerateWithEngine(ctx context.Context, eng engine.Engine, description string, outputJSON bool, display *engine.Display) (string, error) {
	// Load prd skill content
	prdSkill, err := skills.LoadSkill("prd")
	if err != nil {
		return "", fmt.Errorf("failed to load prd skill: %w", err)
	}

	// Get project context
	projectInfo := getProjectContext()

	// Phase 1: Generate clarifying questions
	fmt.Println("Analyzing feature and generating questions...")
	questions, err := generateQuestions(ctx, eng, prdSkill, description, projectInfo, display)
	if err != nil {
		return "", fmt.Errorf("failed to generate questions: %w", err)
	}

	// Collect answers from user
	answers, err := collectAnswers(questions)
	if err != nil {
		return "", fmt.Errorf("failed to collect answers: %w", err)
	}

	// Phase 2: Generate PRD
	fmt.Println("\nGenerating PRD...")
	prdContent, err := generatePRD(ctx, eng, prdSkill, description, answers, projectInfo, display)
	if err != nil {
		return "", fmt.Errorf("failed to generate PRD: %w", err)
	}

	// Determine output path and write
	var outputPath string
	if outputJSON {
		outputPath = filepath.Join(".goralph", "prd.json")
		// Convert to JSON using ralph skill
		ralphSkill, err := skills.LoadSkill("ralph")
		if err != nil {
			return "", fmt.Errorf("failed to load ralph skill: %w", err)
		}
		jsonContent, err := convertPRDToJSON(ctx, eng, ralphSkill, prdContent, display)
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
		// Write markdown to .goralph/
		featureName := extractFeatureNameFromDescription(description)
		outputPath = filepath.Join(".goralph", fmt.Sprintf("prd-%s.md", featureName))
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
	} else {
		response, err = eng.Prompt(ctx, prompt)
	}
	if err != nil {
		return nil, err
	}

	return parseQuestionsResponse(response)
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

func collectAnswers(questions []Question) (map[int]string, error) {
	answers := make(map[int]string)
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("\nPlease answer the following questions:")
	fmt.Println("(Enter letter like 'A' or 'B', or type your own answer for 'Other')")
	fmt.Println()

	for _, q := range questions {
		fmt.Printf("%d. %s\n", q.Number, q.Text)
		for _, opt := range q.Options {
			fmt.Printf("   %s. %s\n", opt.Letter, opt.Label)
		}
		fmt.Print("\nYour answer: ")

		input, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		input = strings.TrimSpace(input)

		// Check if it's a letter option
		upperInput := strings.ToUpper(input)
		for _, opt := range q.Options {
			if opt.Letter == upperInput {
				if strings.Contains(strings.ToLower(opt.Label), "other") {
					fmt.Print("Please specify: ")
					custom, err := reader.ReadString('\n')
					if err != nil {
						return nil, err
					}
					answers[q.Number] = strings.TrimSpace(custom)
				} else {
					answers[q.Number] = opt.Label
				}
				break
			}
		}
		if _, ok := answers[q.Number]; !ok {
			// User typed custom answer
			answers[q.Number] = input
		}
		fmt.Println()
	}

	return answers, nil
}

func generatePRD(ctx context.Context, eng engine.Engine, skill, description string, answers map[int]string, projectInfo string, display *engine.Display) (string, error) {
	// Format answers
	var answerText strings.Builder
	for i := 1; i <= len(answers); i++ {
		if ans, ok := answers[i]; ok {
			answerText.WriteString(fmt.Sprintf("%d. %s\n", i, ans))
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
- Include "Verify in browser using dev-browser skill" for UI stories
- Order: schema changes → backend → frontend

Return ONLY the markdown PRD content (no JSON, no code blocks wrapping it).`, skill, projectInfo, description, answerText.String())

	if display != nil {
		return eng.StreamPrompt(ctx, prompt, display)
	}
	return eng.Prompt(ctx, prompt)
}

func convertPRDToJSON(ctx context.Context, eng engine.Engine, skill, prdContent string, display *engine.Display) (string, error) {
	prompt := fmt.Sprintf(`Convert this markdown PRD to JSON format.

<skill>
%s
</skill>

<markdown>
%s
</markdown>

Return ONLY the JSON (no markdown code blocks, no explanation).
Format must match:
{
  "project": "...",
  "branchName": "ralph/...",
  "description": "...",
  "userStories": [...]
}`, skill, prdContent)

	var response string
	var err error
	if display != nil {
		response, err = eng.StreamPrompt(ctx, prompt, display)
	} else {
		response, err = eng.Prompt(ctx, prompt)
	}
	if err != nil {
		return "", err
	}

	// Extract and validate JSON
	return extractJSONFromResponse(response)
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
