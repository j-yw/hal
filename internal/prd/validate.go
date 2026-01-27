package prd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/jywlabs/goralph/internal/engine"
	"github.com/jywlabs/goralph/internal/skills"
)

// ValidateWithEngine validates a PRD using the ralph skill via an engine.
func ValidateWithEngine(ctx context.Context, eng engine.Engine, prdPath string, display *engine.Display) (*ValidationResult, error) {
	// Load prd.json content
	prdContent, err := os.ReadFile(prdPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read PRD: %w", err)
	}

	// Load ralph skill content
	ralphSkill, err := skills.LoadSkill("ralph")
	if err != nil {
		return nil, fmt.Errorf("failed to load ralph skill: %w", err)
	}

	// Build validation prompt
	prompt := buildValidationPrompt(ralphSkill, string(prdContent))

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

	return result, nil
}

func buildValidationPrompt(skill, prdContent string) string {
	return fmt.Sprintf(`You are a PRD validator. Using the ralph skill rules below, validate this PRD.

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
