package prd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/archive"
	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/skills"
	"github.com/jywlabs/hal/internal/template"
)

// ConvertWithEngine converts a markdown PRD to JSON using the hal skill via an engine.
// If mdPath is empty, the most recent prd-*.md in .hal/ is used.
func ConvertWithEngine(ctx context.Context, eng engine.Engine, mdPath, outPath string, display *engine.Display) error {
	// Load hal skill content
	halSkill, err := skills.LoadSkill("hal")
	if err != nil {
		return fmt.Errorf("failed to load hal skill: %w", err)
	}

	mdSource := mdPath
	if mdSource == "" {
		mdSource, err = findLatestPRDMarkdown(template.HalDir)
		if err != nil {
			return err
		}
	}

	mdContent, err := os.ReadFile(mdSource)
	if err != nil {
		return fmt.Errorf("failed to read markdown PRD: %w", err)
	}

	if halDir, ok := halDirForOutput(outPath); ok {
		opts := archive.CreateOptions{ExcludePaths: []string{mdSource}}
		hasState, err := archive.HasFeatureStateWithOptions(halDir, opts)
		if err != nil {
			return fmt.Errorf("failed to check existing feature state: %w", err)
		}
		if hasState {
			out := io.Discard
			if display != nil {
				out = display.Writer()
			}
			fmt.Fprintln(out, "  auto-archiving current state...")
			if _, err := archive.CreateWithOptions(halDir, "auto-saved", out, opts); err != nil {
				return fmt.Errorf("failed to auto-archive current state: %w", err)
			}
		}
	}

	// Record output file modification time before conversion (if exists)
	var preModTime time.Time
	if stat, err := os.Stat(outPath); err == nil {
		preModTime = stat.ModTime()
	}

	prompt := buildConversionPrompt(halSkill, string(mdContent))

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

func buildConversionPrompt(skill, mdContent string) string {
	return fmt.Sprintf(`You are a PRD converter. Using the hal skill rules below, convert this markdown PRD to JSON.

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
4. UI stories have "Verify in browser using agent-browser skill (skip if no dev server running)"
5. Acceptance criteria are verifiable (not vague)
6. IDs are sequential (US-001, US-002, etc.)
7. Priority based on dependency order
8. All stories have passes: false and empty notes

Return ONLY the JSON object (no markdown, no explanation). The format must be:
{
  "project": "ProjectName",
  "branchName": "hal/feature-name",
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

func halDirForOutput(outPath string) (string, bool) {
	clean := filepath.Clean(outPath)
	if filepath.Base(clean) != template.PRDFile {
		return "", false
	}
	dir := filepath.Dir(clean)
	if filepath.Base(dir) != template.HalDir {
		return "", false
	}
	return dir, true
}

func findLatestPRDMarkdown(halDir string) (string, error) {
	prdMDs, err := filepath.Glob(filepath.Join(halDir, "prd-*.md"))
	if err != nil {
		return "", fmt.Errorf("failed to scan PRD markdown files: %w", err)
	}
	if len(prdMDs) == 0 {
		return "", fmt.Errorf("no prd-*.md files found in %s", halDir)
	}

	var latestPath string
	var latestTime time.Time
	for _, path := range prdMDs {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if latestPath == "" || info.ModTime().After(latestTime) {
			latestPath = path
			latestTime = info.ModTime()
		}
	}

	if latestPath == "" {
		return "", fmt.Errorf("no prd-*.md files found in %s", halDir)
	}

	return latestPath, nil
}
