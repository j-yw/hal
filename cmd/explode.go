package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jywlabs/goralph/internal/engine"
	"github.com/jywlabs/goralph/internal/skills"
	"github.com/jywlabs/goralph/internal/template"
	"github.com/spf13/cobra"

	// Register available engines
	_ "github.com/jywlabs/goralph/internal/engine/claude"
)

var (
	explodeBranchFlag string
	explodeEngineFlag string
)

var explodeCmd = &cobra.Command{
	Use:   "explode [prd-path]",
	Short: "Break a PRD into granular tasks for autonomous execution",
	Long: `Explode a Product Requirements Document into 8-15 granular tasks.

Each task is sized to be completable in a single agent iteration with
boolean acceptance criteria suitable for autonomous verification.

The output is written to .goralph/prd.json in the userStories format,
compatible with the existing Ralph loop.

Examples:
  goralph explode .goralph/prd-feature.md                    # Explode a PRD
  goralph explode .goralph/prd-feature.md --branch feature   # Set branch name
  goralph explode tasks/my-prd.md --engine claude            # Use specific engine`,
	Args: cobra.ExactArgs(1),
	RunE: runExplode,
}

func init() {
	explodeCmd.Flags().StringVarP(&explodeBranchFlag, "branch", "b", "", "Branch name for output prd.json")
	explodeCmd.Flags().StringVarP(&explodeEngineFlag, "engine", "e", "claude", "Engine to use (claude)")
	rootCmd.AddCommand(explodeCmd)
}

func runExplode(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	prdPath := args[0]

	// Verify PRD file exists
	if _, err := os.Stat(prdPath); os.IsNotExist(err) {
		return fmt.Errorf("PRD file not found: %s", prdPath)
	}

	// Read PRD content
	prdContent, err := os.ReadFile(prdPath)
	if err != nil {
		return fmt.Errorf("failed to read PRD: %w", err)
	}

	// Load explode skill
	explodeSkill, err := skills.LoadSkill("explode")
	if err != nil {
		return fmt.Errorf("failed to load explode skill: %w", err)
	}

	// Create engine
	eng, err := engine.New(explodeEngineFlag)
	if err != nil {
		return fmt.Errorf("failed to create engine: %w", err)
	}

	// Create display
	display := engine.NewDisplay(os.Stdout)

	// Show command header
	display.ShowCommandHeader("Explode", filepath.Base(prdPath), eng.Name())

	// Determine branch name
	branchName := explodeBranchFlag
	if branchName == "" {
		// Extract from PRD filename: prd-feature-name.md -> feature-name
		branchName = extractBranchFromPRDPath(prdPath)
	}

	// Build prompt
	prompt := buildExplodePrompt(explodeSkill, string(prdContent), branchName)

	// Record output file modification time before (if exists)
	outPath := filepath.Join(template.GoralphDir, template.AutoPRDFile)
	var preModTime time.Time
	if stat, err := os.Stat(outPath); err == nil {
		preModTime = stat.ModTime()
	}

	// Execute prompt with streaming display
	response, err := eng.StreamPrompt(ctx, prompt, display)
	if err != nil {
		return fmt.Errorf("engine prompt failed: %w", err)
	}

	// Check if engine wrote the output file directly using tools
	if stat, err := os.Stat(outPath); err == nil && stat.ModTime().After(preModTime) {
		// Engine wrote the file - validate it
		content, err := os.ReadFile(outPath)
		if err != nil {
			return fmt.Errorf("failed to read engine-written prd.json: %w", err)
		}

		// Validate JSON structure
		var prd engine.PRD
		if err := json.Unmarshal(content, &prd); err != nil {
			return fmt.Errorf("engine wrote invalid JSON: %w", err)
		}

		// Re-marshal with proper formatting
		formatted, err := json.MarshalIndent(prd, "", "  ")
		if err != nil {
			return err
		}

		// Write formatted version back
		if err := os.WriteFile(outPath, formatted, 0644); err != nil {
			return fmt.Errorf("failed to write formatted prd.json: %w", err)
		}

		taskCount := countTasks(&prd)
		display.ShowCommandSuccess("Tasks generated", fmt.Sprintf("%d tasks • Path: %s", taskCount, outPath))
		return nil
	}

	// Fallback: Parse JSON from text response
	prdJSON, err := extractJSONFromExplodeResponse(response)
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

	// Parse to get task count for success message
	var prd engine.PRD
	json.Unmarshal([]byte(prdJSON), &prd)
	taskCount := countTasks(&prd)

	display.ShowCommandSuccess("Tasks generated", fmt.Sprintf("%d tasks • Path: %s", taskCount, outPath))
	return nil
}

func buildExplodePrompt(skill, prdContent, branchName string) string {
	return fmt.Sprintf(`You are a PRD task breakdown agent. Follow the explode skill instructions below.

<skill>
%s
</skill>

<prd>
%s
</prd>

Branch name to use: %s

Break down this PRD into 8-15 granular tasks following the skill rules:
1. Each task completable in ONE agent iteration
2. Tasks ordered by dependency (types → logic → integration → verification)
3. Every task has boolean acceptance criteria
4. Every task ends with "Typecheck passes"
5. Use T-XXX IDs (T-001, T-002, etc.)
6. All tasks have passes: false and empty notes

Write the JSON directly to .goralph/auto-prd.json using the Write tool.`, skill, prdContent, branchName)
}

func extractBranchFromPRDPath(prdPath string) string {
	base := filepath.Base(prdPath)
	// Remove extension
	name := base[:len(base)-len(filepath.Ext(base))]
	// Remove prd- prefix if present
	if len(name) > 4 && name[:4] == "prd-" {
		name = name[4:]
	}
	return name
}

func extractJSONFromExplodeResponse(response string) (string, error) {
	// Same logic as convert.go but for explode
	response = trimWhitespace(response)

	// Handle markdown code blocks
	if containsCodeBlock(response) {
		response = extractFromCodeBlock(response)
	}

	// Find JSON object
	start := findFirst(response, '{')
	end := findLast(response, '}')
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

func trimWhitespace(s string) string {
	// Manual trim to avoid importing strings just for this
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

func containsCodeBlock(s string) bool {
	for i := 0; i < len(s)-2; i++ {
		if s[i] == '`' && s[i+1] == '`' && s[i+2] == '`' {
			return true
		}
	}
	return false
}

func extractFromCodeBlock(response string) string {
	var result []byte
	inBlock := false
	lines := splitLines(response)
	for _, line := range lines {
		if len(line) >= 3 && line[0] == '`' && line[1] == '`' && line[2] == '`' {
			inBlock = !inBlock
			continue
		}
		if inBlock {
			result = append(result, line...)
			result = append(result, '\n')
		}
	}
	return string(result)
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func findFirst(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func findLast(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func countTasks(prd *engine.PRD) int {
	if len(prd.UserStories) > 0 {
		return len(prd.UserStories)
	}
	return len(prd.Tasks)
}
