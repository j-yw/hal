package prd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jywlabs/goralph/internal/engine"
	"github.com/jywlabs/goralph/internal/skills"
	"github.com/jywlabs/goralph/internal/template"
)

// ConvertWithEngine converts a markdown PRD to JSON using the ralph skill via an engine.
// If mdPath is empty, the skill instructs Claude to auto-discover PRD files in .goralph/
func ConvertWithEngine(ctx context.Context, eng engine.Engine, mdPath, outPath string, display *engine.Display) error {
	// Load ralph skill content
	ralphSkill, err := skills.LoadSkill("ralph")
	if err != nil {
		return fmt.Errorf("failed to load ralph skill: %w", err)
	}

	// Record output file modification time before conversion (if exists)
	var preModTime time.Time
	if stat, err := os.Stat(outPath); err == nil {
		preModTime = stat.ModTime()
	}

	var prompt string
	if mdPath != "" {
		// Explicit path provided - read and embed content
		mdContent, err := os.ReadFile(mdPath)
		if err != nil {
			return fmt.Errorf("failed to read markdown PRD: %w", err)
		}

		// Archive existing PRD if different feature
		if err := archiveExistingPRD(outPath, mdPath); err != nil {
			// Log warning but continue
			fmt.Fprintf(os.Stderr, "warning: failed to archive existing PRD: %v\n", err)
		}

		prompt = buildConversionPrompt(ralphSkill, string(mdContent))
	} else {
		// Auto-discover mode - skill tells Claude to find the file
		prompt = buildDiscoveryPrompt(ralphSkill)
	}

	// Execute prompt
	var response string
	var err2 error
	if display != nil {
		response, err2 = eng.StreamPrompt(ctx, prompt, display)
	} else {
		response, err2 = eng.Prompt(ctx, prompt)
	}
	if err2 != nil {
		return fmt.Errorf("engine prompt failed: %w", err2)
	}

	// Check if Claude wrote the output file directly using tools
	// (file exists and was modified after we started)
	if stat, err := os.Stat(outPath); err == nil && stat.ModTime().After(preModTime) {
		// Claude wrote the file - validate it and return success
		content, err := os.ReadFile(outPath)
		if err != nil {
			return fmt.Errorf("failed to read Claude-written prd.json: %w", err)
		}

		// Validate JSON structure
		var prd engine.PRD
		if err := json.Unmarshal(content, &prd); err != nil {
			return fmt.Errorf("Claude wrote invalid JSON: %w", err)
		}

		// Re-marshal with proper formatting to ensure consistent output
		formatted, err := json.MarshalIndent(prd, "", "  ")
		if err != nil {
			return err
		}

		// Write formatted version back
		if err := os.WriteFile(outPath, formatted, 0644); err != nil {
			return fmt.Errorf("failed to write formatted prd.json: %w", err)
		}

		return nil
	}

	// Fallback: Parse and validate JSON from text response
	prdJSON, err := extractJSONFromResponse(response)
	if err != nil {
		return fmt.Errorf("failed to extract JSON from response: %w", err)
	}

	// Ensure output directory exists
	outDir := filepath.Dir(outPath)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write prd.json
	if err := os.WriteFile(outPath, []byte(prdJSON), 0644); err != nil {
		return fmt.Errorf("failed to write prd.json: %w", err)
	}

	return nil
}

func buildDiscoveryPrompt(skill string) string {
	return fmt.Sprintf(`You are a PRD converter. Follow the ralph skill instructions below.

<skill>
%s
</skill>

Find the PRD markdown file in .goralph/ (look for prd-*.md files) and convert it to prd.json following the skill rules.

Rules for finding the PRD file:
1. Look in .goralph/ directory for files matching prd-*.md
2. If one file exists, use it
3. If multiple files exist, use the most recently modified one
4. If no files found, respond with an error message

After finding the file, convert it following the skill rules:
1. Each story must be completable in ONE iteration (split large stories)
2. Stories ordered by dependency (schema → backend → UI)
3. Every story has "Typecheck passes" as acceptance criteria
4. UI stories have "Verify in browser using dev-browser skill"
5. Acceptance criteria are verifiable (not vague)
6. IDs are sequential (US-001, US-002, etc.)
7. Priority based on dependency order
8. All stories have passes: false and empty notes

Return ONLY the JSON object (no markdown, no explanation). The format must be:
{
  "project": "ProjectName",
  "branchName": "ralph/feature-name",
  "description": "Feature description",
  "userStories": [
    {
      "id": "US-001",
      "title": "Story title",
      "description": "As a user, I want X so that Y",
      "acceptanceCriteria": ["Criterion 1", "Criterion 2", "Typecheck passes"],
      "priority": 1,
      "passes": false,
      "notes": ""
    }
  ]
}`, skill)
}

func buildConversionPrompt(skill, mdContent string) string {
	return fmt.Sprintf(`You are a PRD converter. Using the ralph skill rules below, convert this markdown PRD to JSON.

<skill>
%s
</skill>

<markdown>
%s
</markdown>

Convert the markdown PRD to JSON format following the skill rules:
1. Each story must be completable in ONE iteration (split large stories)
2. Stories ordered by dependency (schema → backend → UI)
3. Every story has "Typecheck passes" as acceptance criteria
4. UI stories have "Verify in browser using dev-browser skill"
5. Acceptance criteria are verifiable (not vague)
6. IDs are sequential (US-001, US-002, etc.)
7. Priority based on dependency order
8. All stories have passes: false and empty notes

Return ONLY the JSON object (no markdown, no explanation). The format must be:
{
  "project": "ProjectName",
  "branchName": "ralph/feature-name",
  "description": "Feature description",
  "userStories": [
    {
      "id": "US-001",
      "title": "Story title",
      "description": "As a user, I want X so that Y",
      "acceptanceCriteria": ["Criterion 1", "Criterion 2", "Typecheck passes"],
      "priority": 1,
      "passes": false,
      "notes": ""
    }
  ]
}`, skill, mdContent)
}

func extractJSONFromResponse(response string) (string, error) {
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
		return "", fmt.Errorf("no JSON found in response")
	}
	response = response[start : end+1]

	// Validate JSON by parsing it
	var prd engine.PRD
	if err := json.Unmarshal([]byte(response), &prd); err != nil {
		return "", fmt.Errorf("invalid JSON: %w", err)
	}

	// Re-marshal with proper formatting
	formatted, err := json.MarshalIndent(prd, "", "  ")
	if err != nil {
		return "", err
	}

	return string(formatted), nil
}

func archiveExistingPRD(prdPath, newMdPath string) error {
	// Check if existing prd.json exists
	existingContent, err := os.ReadFile(prdPath)
	if os.IsNotExist(err) {
		return nil // No existing PRD, nothing to archive
	}
	if err != nil {
		return err
	}

	// Parse existing PRD
	var existingPRD engine.PRD
	if err := json.Unmarshal(existingContent, &existingPRD); err != nil {
		return err
	}

	// Extract feature name from new markdown file
	newFeature := extractFeatureName(newMdPath)
	existingFeature := extractFeatureFromBranch(existingPRD.BranchName)

	// If same feature, no need to archive
	if newFeature == existingFeature {
		return nil
	}

	// Archive existing PRD
	prdDir := filepath.Dir(prdPath)
	archiveDir := filepath.Join(prdDir, "archive", fmt.Sprintf("%s-%s", time.Now().Format("2006-01-02"), existingFeature))
	if err := os.MkdirAll(archiveDir, 0755); err != nil {
		return err
	}

	// Copy prd.json to archive
	archivePRDPath := filepath.Join(archiveDir, template.PRDFile)
	if err := os.WriteFile(archivePRDPath, existingContent, 0644); err != nil {
		return err
	}

	// Copy progress.txt if it exists
	progressPath := filepath.Join(prdDir, "progress.txt")
	if progressContent, err := os.ReadFile(progressPath); err == nil {
		archiveProgressPath := filepath.Join(archiveDir, "progress.txt")
		// Best-effort archive of progress; failures shouldn't block conversion.
		if err := os.WriteFile(archiveProgressPath, progressContent, 0644); err != nil {
			_ = err // Intentionally ignore write errors for the optional archive copy.
		}
	}

	return nil
}

func extractFeatureName(mdPath string) string {
	base := filepath.Base(mdPath)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	name = strings.TrimPrefix(name, "prd-")
	return name
}

func extractFeatureFromBranch(branchName string) string {
	name := strings.TrimPrefix(branchName, "ralph/")
	return name
}
