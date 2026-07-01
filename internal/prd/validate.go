package prd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/skills"
)

// ValidateWithEngine validates a PRD using the hal skill via an engine.
func ValidateWithEngine(ctx context.Context, eng engine.Engine, prdPath string, display *engine.Display) (*ValidationResult, error) {
	// Load prd.json content
	prdContent, err := os.ReadFile(prdPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read PRD: %w", err)
	}

	deterministicResult, deterministicIssues, err := validateParsedPRDContent(prdContent)
	if err != nil {
		return deterministicResult, nil
	}

	// Load hal skill content
	halSkill, err := skills.LoadSkill("hal")
	if err != nil {
		return nil, fmt.Errorf("failed to load hal skill: %w", err)
	}

	// Build validation prompt
	prompt := buildValidationPrompt(halSkill, string(prdContent))

	// Execute prompt
	var response string
	var err2 error
	if display != nil {
		response, err2 = eng.StreamPrompt(ctx, prompt, display)
	} else {
		response, err2 = eng.Prompt(ctx, prompt)
	}
	if err2 != nil {
		return nil, fmt.Errorf("engine prompt failed: %w", err2)
	}

	// Parse response
	result, err := parseValidationResponse(response)
	if err != nil {
		return nil, fmt.Errorf("failed to parse validation response: %w", err)
	}

	applyDeterministicValidationIssues(result, deterministicIssues)
	return result, nil
}

func buildValidationPrompt(skill, prdContent string) string {
	return fmt.Sprintf(`You are a PRD validator. Using the hal skill rules below, validate this PRD.

<skill>
%s
</skill>

<prd>
%s
</prd>

Validate the PRD against these rules from the skill:
1. Each story must be completable in ONE iteration (small scope)
2. Stories are ordered by dependency (schema → backend → UI)
3. Every story has "Typecheck passes" as a criterion
4. UI stories have "Verify in browser" as a criterion
5. Acceptance criteria are verifiable (not vague like "works correctly")
6. No story depends on a later story
7. Scheduling fields are valid: dependsOn references known earlier IDs, no duplicate IDs, no self-dependencies, no dependency cycles, and parallelSafe/barrier entries include parallelReason

Return ONLY a JSON object (no markdown, no explanation) in this exact format:
{"valid": true/false, "errors": [{"storyId": "US-XXX", "field": "field_name", "message": "description", "severity": "error"}], "warnings": [{"storyId": "US-XXX", "field": "field_name", "message": "description", "severity": "warning"}]}

If valid with no issues: {"valid": true, "errors": [], "warnings": []}`, skill, prdContent)
}

func parseValidationResponse(response string) (*ValidationResult, error) {
	// Try to extract JSON from response
	response = strings.TrimSpace(response)

	// Handle markdown code blocks
	if strings.HasPrefix(response, "```") {
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

	// Find JSON object in response
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")
	if start == -1 || end == -1 || end < start {
		return nil, fmt.Errorf("no JSON found in response")
	}
	response = response[start : end+1]

	var result ValidationResult
	if err := json.Unmarshal([]byte(response), &result); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	return &result, nil
}

func validateParsedPRDContent(prdContent []byte) (*ValidationResult, []Issue, error) {
	var parsed engine.PRD
	if err := json.Unmarshal(prdContent, &parsed); err != nil {
		result := &ValidationResult{
			Valid: false,
			Errors: []Issue{{
				Field:    "json",
				Message:  fmt.Sprintf("invalid PRD JSON: %v", err),
				Severity: "error",
			}},
		}
		return result, nil, err
	}

	return nil, ValidateSchedulingDependencies(&parsed), nil
}

func applyDeterministicValidationIssues(result *ValidationResult, issues []Issue) {
	if result == nil || len(issues) == 0 {
		return
	}

	result.Errors = append(result.Errors, issues...)
	for _, issue := range issues {
		if issue.Severity == "error" {
			result.Valid = false
			return
		}
	}
}

// ValidateSchedulingDependencies returns deterministic validation errors for
// PRD scheduling metadata that must not depend on model judgment.
func ValidateSchedulingDependencies(prd *engine.PRD) []Issue {
	if prd == nil {
		return nil
	}

	stories := schedulingStories(prd)
	known := make(map[string]int, len(stories))
	var issues []Issue
	for index, story := range stories {
		id := strings.TrimSpace(story.ID)
		if id == "" {
			continue
		}
		if _, exists := known[id]; exists {
			issues = append(issues, Issue{
				StoryID:  id,
				Field:    "id",
				Message:  fmt.Sprintf("%s duplicates an earlier story/task ID", id),
				Severity: "error",
			})
			continue
		}
		known[id] = index
	}

	graph := make(map[string][]string, len(stories))
	for index, story := range stories {
		storyID := strings.TrimSpace(story.ID)
		if storyID == "" {
			continue
		}

		if (story.ParallelSafe != nil || story.Barrier) && strings.TrimSpace(story.ParallelReason) == "" {
			issues = append(issues, Issue{
				StoryID:  storyID,
				Field:    "parallelReason",
				Message:  fmt.Sprintf("%s must include parallelReason when parallelSafe or barrier is set", storyID),
				Severity: "error",
			})
		}

		for _, rawDependency := range story.DependsOn {
			dependencyID := strings.TrimSpace(rawDependency)
			switch {
			case dependencyID == storyID:
				issues = append(issues, Issue{
					StoryID:  storyID,
					Field:    "dependsOn",
					Message:  fmt.Sprintf("%s must not depend on itself", storyID),
					Severity: "error",
				})
			case dependencyID == "":
				issues = append(issues, Issue{
					StoryID:  storyID,
					Field:    "dependsOn",
					Message:  fmt.Sprintf("%s depends on an empty story ID", storyID),
					Severity: "error",
				})
			default:
				dependencyIndex, ok := known[dependencyID]
				if !ok {
					issues = append(issues, Issue{
						StoryID:  storyID,
						Field:    "dependsOn",
						Message:  fmt.Sprintf("%s depends on unknown story ID %s", storyID, dependencyID),
						Severity: "error",
					})
					continue
				}
				if dependencyIndex >= index {
					issues = append(issues, Issue{
						StoryID:  storyID,
						Field:    "dependsOn",
						Message:  fmt.Sprintf("%s depends on later story ID %s", storyID, dependencyID),
						Severity: "error",
					})
				}
				graph[storyID] = append(graph[storyID], dependencyID)
			}
		}
	}

	return append(issues, dependencyCycleIssues(stories, graph)...)
}

func schedulingStories(prd *engine.PRD) []engine.UserStory {
	stories := make([]engine.UserStory, 0, len(prd.UserStories)+len(prd.Tasks))
	stories = append(stories, prd.UserStories...)
	stories = append(stories, prd.Tasks...)
	return stories
}

func dependencyCycleIssues(stories []engine.UserStory, graph map[string][]string) []Issue {
	state := make(map[string]int, len(stories))
	stack := make([]string, 0, len(stories))
	cycleKeys := make(map[string]struct{})
	var issues []Issue

	var visit func(string)
	visit = func(id string) {
		switch state[id] {
		case 1, 2:
			return
		}

		state[id] = 1
		stack = append(stack, id)
		defer func() {
			stack = stack[:len(stack)-1]
			state[id] = 2
		}()

		dependencies := append([]string(nil), graph[id]...)
		sort.Strings(dependencies)
		for _, dependencyID := range dependencies {
			if state[dependencyID] == 1 {
				cycle := dependencyCyclePath(stack, dependencyID)
				key := strings.Join(cycle, " -> ")
				if _, seen := cycleKeys[key]; seen {
					continue
				}
				cycleKeys[key] = struct{}{}
				issues = append(issues, Issue{
					StoryID:  id,
					Field:    "dependsOn",
					Message:  fmt.Sprintf("dependency cycle detected: %s", key),
					Severity: "error",
				})
				continue
			}
			visit(dependencyID)
		}
	}

	for _, story := range stories {
		id := strings.TrimSpace(story.ID)
		if id == "" {
			continue
		}
		visit(id)
	}

	return issues
}

func dependencyCyclePath(stack []string, dependencyID string) []string {
	start := 0
	for i, id := range stack {
		if id == dependencyID {
			start = i
			break
		}
	}

	cycle := append([]string(nil), stack[start:]...)
	cycle = append(cycle, dependencyID)
	return cycle
}

// FormatValidationResult formats the validation result for display.
func FormatValidationResult(result *ValidationResult) string {
	var sb strings.Builder

	if result.Valid {
		sb.WriteString("PRD is valid\n")
	} else {
		sb.WriteString("PRD validation failed\n")
	}

	if len(result.Errors) > 0 {
		sb.WriteString("\nErrors:\n")
		for _, err := range result.Errors {
			if err.StoryID != "" {
				sb.WriteString(fmt.Sprintf("  [%s] %s: %s\n", err.StoryID, err.Field, err.Message))
			} else {
				sb.WriteString(fmt.Sprintf("  %s\n", err.Message))
			}
		}
	}

	if len(result.Warnings) > 0 {
		sb.WriteString("\nWarnings:\n")
		for _, warn := range result.Warnings {
			if warn.StoryID != "" {
				sb.WriteString(fmt.Sprintf("  [%s] %s: %s\n", warn.StoryID, warn.Field, warn.Message))
			} else {
				sb.WriteString(fmt.Sprintf("  %s\n", warn.Message))
			}
		}
	}

	return sb.String()
}
